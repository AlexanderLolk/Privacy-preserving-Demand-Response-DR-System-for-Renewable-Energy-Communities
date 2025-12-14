import time
import src.dso.DSO                  as distributer
import src.smartmeters.smartmeter   as smart_meter
import src.aggregators.aggregator   as energy_aggregator
import src.aggregators.dr           as dr_aggregator
import src.boards.board             as board
import src.utils.eval               as eval
from src.utils.elgamal_dec_proof import verify_partial_decryption_share

# THIS IS A COPY OF MAIN, THAT ARE JUST FOR TESTING DIFFERENT PERFORMANCES VALUES

def log_phase(name, start_time):
    duration = time.time() - start_time
    print(f"[PERFORMANCE] {name} completed in {duration:.4f} seconds")

if __name__ == "__main__":

    # ---------------------------------------------------------
    # SYSTEM SETUP & INSTANTIATION
    # ---------------------------------------------------------
    start_time = time.time()
    print("\n\nSYSTEM SETUP & INSTANTIATION STARTED\n\n")

    # Initialize the Trusted Authority / Distribution System Operator
    dso = distributer.DSO()

    NUM_SM      = 13     # Total Smart Meters
    NUM_AGG     = 1      # Energy Aggregator
    NUM_DR_AGG  = 1      # DR Aggregator
    
    # Define how many users will actually try to join the event
    NUM_PARTICIPANTS = NUM_SM - 4

    # And how many is selected by the DR aggregator
    NUM_SELECTED = NUM_PARTICIPANTS // 2

    sms     = []
    aggs    = []
    dr_aggs = []
    
    # Create entities
    for i in range(NUM_SM):
        sms.append(smart_meter.SmartMeter(init_id="sm_id_" + str(i)))
    
    for i in range(NUM_AGG):
        aggs.append(energy_aggregator.Aggregator(init_id="agg_id_" + str(i)))
        
    for i in range(NUM_DR_AGG):
        dr_aggs.append(dr_aggregator.DR_Aggregator(init_id="dr_agg_id_" + str(i)))
       
    # Extract public keys for registration
    sm_info     = [(smartmeter.id, smartmeter.get_public_key()) for smartmeter in sms]
    agg_info    = [(aggregator.id, aggregator.get_public_key()) for aggregator in aggs]
    dr_info     = [(dr.id, dr.get_public_key()) for dr in dr_aggs]  

    # Since there is only one
    agg = aggs[0]
    dr_agg = dr_aggs[0]
    log_phase("SYSTEM SETUP & INSTANTIATION", start_time)

    # ---------------------------------------------------------
    # REGISTRATION & VERIFICATION (PK_i)
    # ---------------------------------------------------------
    start_time = time.time()
    print("\n\nREGISTRATION & VERIFICATION STARTED\n\n")

    # The DSO verifies the Zero-Knowledge Proofs (NIZKPs) of all entities
    # to ensure they own their keys before registering them.
    for smart_meter in sm_info:
        dso.verify_smartmeter(smart_meter)
    
    for energy_aggregator in agg_info:
        dso.verify_aggregator(energy_aggregator)
    
    for dr_aggregator in dr_info:
        dso.verify_dr_aggregator(dr_aggregator)
    
    # Initialize the Board
    bb = board.Board()

    # DSO publishes its keys (Signing + Encryption) to the Board
    bb.publish_dso_public_keys((dso.get_public_key(), dso.get_encryption_key()))
    
    # DSO publishes the signed list of all verified participants
    bb.publish_smartmeters_and_aggregators(dso.sign_registered_lists())
    
    # DSO publishes the Noisy List (Encrypted Zero-Reports)
    noisy_target_reduction = dso.generate_noisy_list()
    bb.publish_target_reduction(noisy_target_reduction)
    
    log_phase("REGISTRATION & VERIFICATION", start_time)


    # ---------------------------------------------------------
    # KEY DISTRIBUTION
    # ---------------------------------------------------------
    start_time = time.time()
    print("\n\nKEY DISTRIBUTION STARTED\n\n")

    # Entities fetch DSO keys from the Board
    for smart_meter in sms:
        smart_meter.set_dso_public_keys(bb.pk, bb.ek)
        
    for energy_aggregator in aggs:
        energy_aggregator.set_dso_public_keys(bb.pk, bb.ek)
        
    for dr_aggregator in dr_aggs:
        dr_aggregator.set_dso_public_keys(bb.pk, bb.ek)
    
    # DSO distributes the Aggregator's specific encryption key
    for energy_aggregator in aggs:
        dso.set_agg_encryption_key(energy_aggregator.get_agg_id_And_encryption_key())
        
    for dr_aggregator in dr_aggs:
        dso.set_agg_encryption_key(dr_aggregator.get_dr_agg_id_And_encryption_key(), dr_agg=True)

    # --- Threshold Key Share Distribution ---
    # This should happen over secure channels (SSL/TLS) in production.
    # Here we simulate it by passing the share directly via `encrypt_dk_and_send_to_agg`.

    # Energy Aggregator gets Share #1
    for energy_aggregator in aggs:
        energy_aggregator.thresh_params = dso.get_threshold_params()
        share = dso.encrypt_dk_and_send_to_agg(energy_aggregator.id)
        energy_aggregator.set_dso_dk(share)

    # DR Aggregator gets Share #2
    for dr_aggregator in dr_aggs:
        dr_aggregator.thresh_params = dso.get_threshold_params()
        share = dso.encrypt_dk_and_send_to_agg(dr_aggregator.id)
        dr_aggregator.set_dso_dk(share)

    # Smart Meters fetch the Aggregator's public key (to verify future messages)
    for smart_meter in sms:
        smart_meter.set_agg_public_keys(bb.register_aggregator[0][1])

    log_phase("KEY DISTRIBUTION", start_time)

    # ---------------------------------------------------------
    # MIX PHASE (Anonymization Setup)
    # ---------------------------------------------------------
    start_time = time.time()
    print("\n\nMIX PHASE STARTED\n\n")

    # The Aggregator shuffles the list of Smart Meter Public Keys
    agg.create_mixed_anon_pk_set(sm_info)

    # Publish the Shuffled Keys (pk') and the Shuffle Proof (πmix) to the Board
    bb.publish_mix_pk_and_proof(agg.publish_mixed_keys())
    
    # Smart Meters retrieve the Aggregator's encryption key to receive their anon IDs
    for smartmeter in sms:
        agg.set_sm_encrypytion_keys(smartmeter.get_sm_id_And_encryption_key(), bb.get_sm_pk_by_id(smartmeter.id))

    # Smart Meters retrieve their specific blinding factor to recognize their new anonymous ID
    for smartmeter in sms:
        ### some method for the smartmeter to get the anon_pk
        smartmeter.set_anon_key(agg.set_anon_key_mix(smartmeter.get_public_key(), smartmeter.id))
        print(f"Smartmeter {smartmeter.id} got anon key mix.")

    log_phase("MIX PHASE", start_time)

    # ---------------------------------------------------------
    # REPORT PHASE (Baseline Submission)
    # ---------------------------------------------------------
    start_time = time.time()
    print("\n\nBASELINE REPORT PHASE STARTED\n\n")

    report_user_info = sm_info

    # Simulate User Behavior (placeholder)
    # Some users participate (send m=10), others do not (send m=0).
    for i, smartmeter in enumerate(sms):
        if i < NUM_PARTICIPANTS:
            m = 10
        else:
            m = 0 # non-participating user sends 0 report


        # Smart Meter encrypts and signs the report
        report_data = smartmeter.get_sm_baseline(m)
        print(f"Smartmeter {smartmeter.id} sent report.")
        
        # Energy Aggregator collects the report
        # Internally, check_sm_report verifies if m=0 (via deterministic enc) to filter participants
        agg.check_sm_baseline(report_data, smartmeter.id)
    
    # Aggregator publishes list of anonymized participants found to the Board
    bb.publish_participants(agg.get_participants())

    log_phase("BASELINE REPORT PHASE", start_time)

    # ---------------------------------------------------------
    # ANONYM PHASE (Publishing Baseline)
    # ---------------------------------------------------------
    start_time = time.time()
    print("\n\nANONYM PHASE STARTED\n")

    # Aggregator anonymizes the batch of valid baseline reports
    anonym_bb, anonym_pbb = agg.make_anonym_baseline()
    
    # Publish baseline reports
    bb.publish_baseline_anonym_reports(anonym_bb, agg.id)

    # Publish consumption reports
    bb.publish_consumption_anonym_reports(anonym_pbb)

    log_phase("ANONYM PHASE", start_time)

    # ---------------------------------------------------------
    # SELECTION PHASE (event)
    # ---------------------------------------------------------
    start_time = time.time()
    print("\n\nSELECTION PHASE STARTED\n")
    
    participants = agg.get_participants()
    
    # DR Aggregator retrieves the list of anonymous candidates
    dr_agg.set_pseudo_anonymous_iden(participants)
    
    # DR Aggregator selects participants
    dr_agg.select_random_sms(NUM_SELECTED)

    # Publish selected Smart meters (signed by DR Agg) to the Board
    bb.publish_selected_sm(dr_agg.get_selected())
    
    # Smart Meters check the Board to see if they won
    for smart_meter in sms:
        smart_meter.check_if_in_event(bb.get_selected_sm())

    log_phase("SELECTION PHASE", start_time)

    # ---------------------------------------------------------
    # CONSUMPTION PHASE (Actual Usage Submission)
    # ---------------------------------------------------------
    start_time = time.time()
    print("\n\nCONSUMPTION PHASE STARTED\n")
    print("\n\nGetting sm's consumption reports.\n\n")

    # Only selected participants send their actual consumption data
    for smartmeter in sms:
        if smartmeter.is_participating():
            comsumption_report = smartmeter.get_sm_consumption()
            print(f"Smartmeter {smartmeter.id} sent comsuption.")
            agg.check_sm_consumption(comsumption_report, smartmeter.id)
        else:
            print(f"Smartmeter {smartmeter.id} is not a participant.")

    # Aggregator anonymizes and publishes the consumption reports
    _, consumption_anonym_pbb = agg.make_anonym_consumption()
    bb.publish_sm_comsumption_PBB(consumption_anonym_pbb)

    log_phase("CONSUMPTION PHASE", start_time)

    # ---------------------------------------------------------
    # EVALUATION PHASE
    # ---------------------------------------------------------
    start_time = time.time()
    print("\n\nEVAL PHASE STARTED")

    # Eval is called for each aggregator
    print("")

    evaluator = eval.Eval(dso.get_encryption_key())

    # Partial Decryption of Reports
    # Both Aggregators download encrypted reports (Baseline & Consumption) from the Board
    # and compute their partial decryption shares.
    agg_share, agg_proof = agg.partial_dec_reports(bb.get_sm_baseline(), bb.get_sm_consumption())
    dr_share, dr_proof = dr_agg.partial_dec_reports(bb.get_sm_baseline(), bb.get_sm_consumption())
    
    # TODO CHECK PARTIAL PROOF with agg encryption
    if not verify_partial_decryption_share(agg.pp, agg_proof[0][0], agg_proof[1]):
        raise ValueError("Aggregator partial decryption share proof verification failed!")
    
    if not verify_partial_decryption_share(dr_agg.pp, dr_proof[0][0], dr_proof[1]):
        raise ValueError("Dr Aggregator partial decryption share proof verification failed!")
    
    
    # Homomorphic calculation and checking (placeholder values)
    # The Evaluator combines shares to check if Baseline - Consumption >= Target 
    # Right now it returns a list of "Equal Ciphertexts" for successful users.
    equal_cts, proofs = evaluator.eval(bb, bb, agg_share, dr_share)

    if len(equal_cts) < 1:
        print("No smartmeters can be evaluated")
        exit(0)

    # Final decryption of result
    # The aggregators partially decrypt the "Result Ciphertexts" (which should be 0)
    # to prove the evaluation was correct.
    agg_equal_cts_share = agg.partial_dec_equal_cts(equal_cts)
    dr_equal_cts_share = dr_agg.partial_dec_equal_cts(equal_cts)
    
    # Does a final check: Does Decrypt(Result_CT) == 0?
    evaluator.final_check_eval(bb, bb, agg_equal_cts_share, dr_equal_cts_share, (equal_cts, proofs), dso.get_threshold_params())
    log_phase("EVALUATION PHASE", start_time)