import dso.DSO as distributer
import smartmeters.smartmeter as sm
import aggregators.aggregator as agg
import aggregators.dr as dr
import boards.board as board
import boards.privateboard as privateboard
import utils.eval as eval
# from utils.generators import pub_param
# from utils.procedures import Procedures
import threshold_crypto as tc

# Distribution System Operators (DSOs)

# TODO: sign every list 


if __name__ == "__main__":
    
    # pro = Procedures()
    dso = distributer.DSO()

    NUM_SM = 5
    NUM_AGG = 1
    NUM_DR_AGG = 1
    
    sms = []
    aggs = []
    dr_aggs = []
    
    for i in range(NUM_SM):
        sms.append(sm.SmartMeter(init_id="sm_id_" + str(i)))
    
    for i in range(NUM_AGG):
        aggs.append(agg.Aggregator(init_id="agg_id_" + str(i)))
        
    for i in range(NUM_DR_AGG):
        dr_aggs.append(dr.DR_Aggregator(init_id="dr_agg_id_" + str(i)))
       
    # sm_info and agg_info are dictionaries with id as key and public key (pk, pp, proof) as value
    # sm_info = {smartmeter.id: smartmeter.get_public_key() for smartmeter in sms}
    # agg_info = {aggregator.id: aggregator.get_public_key() for aggregator in aggs}

    sm_info = [(smartmeter.id, smartmeter.get_public_key()) for smartmeter in sms]
    agg_info = [(aggregator.id, aggregator.get_public_key()) for aggregator in aggs]
    dr_info = [(dr.id, dr.get_public_key()) for dr in dr_aggs]

    for sm in sm_info:
        dso.verify_smartmeter(sm)
    
    for agg in agg_info:
        dso.verify_aggregator(agg)
    
    for dr in dr_info:
        dso.verify_dr_aggregator(dr)
    
    bb = board.Board()
    bb.publish_dso_public_keys((dso.get_public_key(), dso.get_encryption_key())) # pk (pk, pp, s_proof) and ek (ek, pp, e_proof)
    bb.publish_smartmeters_and_aggregators(dso.sign_registered_lists())
    nois = dso.generate_noisy_list()
    bb.target_reduction(nois) # noisy list from DSO
    print("\ntarget_reduction from main: \n" + str(nois) + "\n")
    
    # TODO Report writing: remember we are trying not to send the full class object info but as little as we can get away with
    for sm in sms:
        sm.set_dso_public_keys(bb.pk, bb.ek)
        
    # TODO for more than one aggregator, we'd probably like some IDs as well
    for agg in aggs:
        agg.set_dso_public_keys(bb.pk, bb.ek)
        
    for dr in dr_aggs:
        dr.set_dso_public_keys(bb.pk, bb.ek)
    
    # TODO needs to be treshhold elgamal, so that share is given instead of the whole key 
    # TODO ALSO this is done with a ssl connection, so we have to make something up for this
    # set_dso_dk
    dso.set_agg_encryption_key([agg.get_agg_id_And_encryption_key() for agg in aggs])
    for agg in aggs:
        agg.set_dso_dk(dso.encrypt_dk_and_send_to_agg(agg.id))
    
    for dr in dr_aggs:
        dr.set_dso_dk(dso.encrypt_dk_and_send_to_agg(dr.id))

    # -------THRESHOLD KEY SETUP START
    aggs[0].dk_share            = dso.key_shares[0]         # Energy aggregator
    aggs[0].thresh_params       = dso.thresh_params       
    dr_aggs[0].dk_share         = dso.key_shares[1]         # DR aggregator
    dr_aggs[0].thresh_params    = dso.thresh_params    
    # -------THRESHOLD KEY SETUP END

    # Give agg pk to sms
    for sm in sms:
        # for now they on get the first one
        sm.set_agg_public_keys(bb.register_aggregator[0][1])

    ##########
    # MIX
    ##########
    mix_agg = aggs[0]
    mix_agg.create_mixed_anon_pk_set(sm_info)

    bb.publish_mix_pk_and_proof(mix_agg.publish_mixed_keys())

    for smartmeter in sms:
        ### some method for the smartmeter to get the anon_pk
        smartmeter.set_anon_key(mix_agg.set_anon_key_mix(smartmeter.get_public_key()))
        print(f"Smartmeter {smartmeter.id} got anon key mix.")

    ##########
    # REPORT
    ##########
    report_user_info = sm_info
    report_agg = aggs[0]
    report_dr_agg = dr_aggs[0]

    # TODO perhaps a different message and a better way of choosing participating vs non-participating users
    for i, smartmeter in enumerate(sms):
        if i < NUM_SM - 3:
            m = 10
        else:
            m = 0 # non-participating user sends 0 report

        report_data = smartmeter.generate_and_send_report(m)
        print(f"Smartmeter {smartmeter.id} sent report.")
        # extracting participants
        report_agg.check_sm_report(report_data, report_dr_agg)
    
    bb.publish_participants(report_agg.get_participants())

    ##########
    # ANONYM
    ##########
    anonym_agg = aggs[0]
    anonym_bb, anonym_pbb = anonym_agg.make_anonym()
    
    # public board
    bb.publish_anonym_reports(anonym_bb, anonym_agg.id)

    # private board
    pbb = privateboard.PrivateBoard()
    pbb.publish_anonym_reports(anonym_pbb)
    print("\"Anonym done\".")

    dr_agg = dr_aggs[0]
    dr_agg.set_psudo_anonymous_iden(pbb.get_participants())
    dr_agg.select_random_sms()
    bb.publish_selected_sm(dr_agg.get_selected())
    
    # step 12 in seq chart
    for sm in sms:
        sm.check_if_in_event(bb.get_selected_sm())

    ##########
    # EVAL
    ##########

    # Publish baseline and target
    bb.publish_baselines(bb.T_r) #
    if getattr(bb, "ct_T", None) is None:
        bb.ct_T = bb.T_r

    # call Eval for each aggregator
    print("")
    print("Aggregator 1 (Energy) running Eval...")
    eval.eval(bb, pbb, aggs[0].dk_share, dso.ek, aggs[0].id)
    print(f"Aggregator 1 posted partial decryption shares.")

    print("Aggregator 2 (DR) running Eval...")
    eval.eval(bb, pbb, dr_aggs[0].dk_share, dso.ek, dr_aggs[0].id)
    print(f"Aggregator 2 posted partial decryption shares.")

    print("Partial evaluation done by both aggregators.")

    # COMBINE SHARES
    eval.combine_decryption_shares(bb, dso.get_threshold_params())