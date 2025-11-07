import dso.DSO as distributer
import smartmeters.smartmeter as sm
import aggregators.aggregator as agg
import boards.board as board

# Distribution System Operators (DSOs)

if __name__ == "__main__":
    # step 1 DSO starts demand response system
    dso = distributer.DSO()
    
    # Step 2 user and agg are created
    NUM_SM = 5
    NUM_AGG = 4
    sms = []
    aggs = []
    
    for i in range(NUM_SM):
        sms.append(sm.SmartMeter(init_id="sm_id_" + str(i)))
    
    for i in range(NUM_AGG):
        aggs.append(agg.Aggregator(init_id="agg_id_" + str(i)))
       
    # step 3 build info for users and aggregator
    # sm_info and agg_info are dictionaries with id as key and public key (pk, pp, proof) as value
    sm_info = {smartmeter.id: smartmeter.get_public_key() for smartmeter in sms}
    agg_info = {aggregator.id: aggregator.get_public_key() for aggregator in aggs}

    # step 4 users and aggregators are verified and then registered
    dso.verify_smartmeter(sm_info)
    dso.verify_aggregator(agg_info)
    
    # step 5 DSO sends board to users and aggregators
    bb = board.Board()
    bb.publish_dso_public_keys((dso.get_public_key(), dso.get_encryption_key())) # pk (pk, pp, s_proof) and ek (ek, pp, e_proof)
    bb.publish_smartmeters_and_aggregators(dso.sign_registered_lists())
    bb.target_reduction(dso.generate_noisy_list())
    
    
    # step 6 give DSO keys to smartmeters and aggregators
    # TODO Report writing: remember we are trying not to send the full class object info but as little as we can get away with
    # verifies the lists with schnorrs signatures
    for sm in sms:
        sm.set_dso_public_keys(bb.pk, bb.ek)
        
    for agg in aggs:
        agg.set_dso_public_keys(bb.pk, bb.ek)

     


