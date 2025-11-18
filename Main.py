import dso.DSO as distributer
import smartmeters.smartmeter as sm
import aggregators.aggregator as agg
import aggregators.dr as dr
import boards.board as board
import boards.privateboard as privateboard
import utils.eval as eval
from utils.generators import pub_param

# Distribution System Operators (DSOs)

# TODO: sign every list 

if __name__ == "__main__":
    
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
        report_agg.check_sm_report(report_data)
    
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

    # -------THRESHOLD KEY SETUP START
    # Need the group order for share generation
    _, _, order = pub_param() 
    
    # Create first share (random)
    dk_share_1 = order.random()
    # Create second share (dso.dk - share1)
    dk_share_2 = (dso.dk - dk_share_1) % order
    
    # Assign the shares to the aggregators.
    aggs[0].dk_share = dk_share_1 # Energy aggregator
    dr_aggs[0].dk_share = dk_share_2 # DR aggregator

    # -------THRESHOLD KEY SETUP END

    # Publish baseline and target
    bb.publish_baselines(bb.T_r)
    if getattr(bb, "ct_T", None) is None:
        bb.ct_T = bb.T_r

    # call Eval for each aggregator
    # Aggregator 1 (Energy) runs Eval and posts its partial decryption
    print("")
    print("Aggregator 1 (Energy) running Eval...")
    eval.Eval(bb, pbb, aggs[0].dk_share, dso.ek, aggs[0].id)
    print(f"Aggregator 1 posted partial decryption shares.")

    # Aggregator 2 (DR) runs Eval and posts its partial decryption
    print("Aggregator 2 (DR) running Eval...")
    eval.Eval(bb, pbb, dr_aggs[0].dk_share, dso.ek, dr_aggs[0].id)
    print(f"Aggregator 2 posted partial decryption shares.")

    print("Partial evaluation done by both aggregators.")

    # COMBINE SHARES
    # This call combines the shares posted on the board to get the
    # final result M_set.
    
    # clean version without debug, dk, and pbb
    eval.combine_decryption_shares(bb)

    # debug version with dk and pbb
    # eval.combine_decryption_shares(bb, pbb, dso.dk)
    
    # eval debugging
    # print(f"Final Eval status: {getattr(bb, 'eval_status', 'Not evaluated')}")
    # print(f"Final M_set result: {getattr(bb, 'M_set', 'Not computed')}")

    # print("reports on private board:", len(getattr(pbb, "ct_t", {})))
    # print("targets on public board (len bb.ct_T):", len(getattr(bb, "ct_T", [])))

    # from utils.ec_elgamal import dec, make_table
    # pp = bb.pk[1]
    # table = make_table(pp)
    # if getattr(bb, "ct_sum", None) is not None:
    #     try:
    #         decoded_sum = dec(dso.dk, pp, table, bb.ct_sum)
    #         decoded_sum_readable = table[decoded_sum] if decoded_sum in table else decoded_sum
    #         print(f"Decoded ct_sum (aggregate reduction) = {decoded_sum_readable}")
    #     except Exception as e:
    #         print(f"Failed to decode ct_sum with DSO dk: {e}")