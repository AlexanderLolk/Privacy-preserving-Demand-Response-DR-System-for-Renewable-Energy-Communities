import dso.DSO as distributer
import smartmeters.smartmeter as sm
import aggregators.aggregator as agg
import aggregators.dr as dr
import boards.board as board
import boards.privateboard as privateboard
import utils.eval as eval

# Distribution System Operators (DSOs)

# TODO: sign every list 

if __name__ == "__main__":
    
    dso = distributer.DSO()

    NUM_SM = 5
    NUM_AGG = 4
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

    # TODO FUNCTION SHOULD NOT BE MADE FOR LISTS
    dso.verify_smartmeter(sm_info)
    dso.verify_aggregator(agg_info)
    dso.verify_dr_aggregator(dr_info)
    
    bb = board.Board()
    bb.publish_dso_public_keys((dso.get_public_key(), dso.get_encryption_key())) # pk (pk, pp, s_proof) and ek (ek, pp, e_proof)
    bb.publish_smartmeters_and_aggregators(dso.sign_registered_lists())

    bb.target_reduction(dso.generate_noisy_list()) # noisy list from DSO
    
    # TODO Report writing: remember we are trying not to send the full class object info but as little as we can get away with
    for sm in sms:
        sm.set_dso_public_keys(bb.pk, bb.ek)
        
    # TODO for more than one aggregator, we'd probably like some IDs as well
    for agg in aggs:
        agg.set_dso_public_keys(bb.pk, bb.ek)
        
    for dr in dr_aggs:
        dr.set_dso_public_keys(bb.pk, bb.ek)
    
    # TODO needs to be threadshold elgamal, so that share is given instead of the whole key 
    # set_dso_dk
    dso.set_agg_encryption_key([agg.get_agg_id_And_encryption_key() for agg in aggs])
    for agg in aggs:
        agg.set_dso_dk(dso.encrypt_dk_and_send_to_agg(agg.id))
    
    for dr in dr_aggs:
        dr.set_dso_dk(dso.encrypt_dk_and_send_to_agg(dr.id))

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

    for i, smartmeter in enumerate(sms):
        if i < NUM_SM - 1:
            m = 10
        else:
            m = 0 # non-participating user sends 0 report

        report_data = smartmeter.generate_and_send_report(m)
        print(f"Smartmeter {smartmeter.id} sent report.") 
        report_agg.set_sm_report(report_data)
    
    bb.publish_sm_reports(report_agg.get_participants())

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
    dr_agg.set_psudo_anonymous_iden(pbb.get_participants)
    dr_agg.select_random_sms()
    bb.publish_selected_sm(dr_agg.get_selected())
    
    ##########
    # EVAL
    ##########

    # TODO use the correct values
    bb.publish_baselines(bb.T_r)
    if getattr(bb, "ct_T", None) is None:
        bb.ct_T = bb.T_r

    eval.Eval(bb, pbb, dso.dk, dso.ek)
    print("Eval done.")
    