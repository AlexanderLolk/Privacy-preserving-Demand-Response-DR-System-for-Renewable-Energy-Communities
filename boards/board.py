# this is both for public and private boards
from utils.signature import schnorr_verify, schnorr_verify_list
from utils.NIZKP import schnorr_NIZKP_verify
from utils.dec_proof import verify_correct_decryption
from utils.shuffle import CheckProof # TODO change name to be more specific like shuffle_verify_proof

class Board:
    
    def publish_dso_public_keys(self, dso_keys):
        
        # (pk, ek)
        (pk, pp, s_proof) = dso_keys[0]
        (ek, _, e_proof) = dso_keys[1]

        if not schnorr_NIZKP_verify(pk, pp, s_proof):
            print("DSO public key proof verification failed")
        
        # Test: write in the report how the test shows how the encryption can be decrypted etc
        if not verify_correct_decryption(ek, pp, e_proof):
            print("DSO encryption key proof verification failed")

        self.pk, self.ek = dso_keys
        
    # The DSO registers and has verified users and aggregators, then sends it to the board
    # TODO rewrite all schnorr_verify name to be schnorr_sign_verify for clarity
    # TODO REFACTOR TO WORK FOR LISTS
    # def publish_smartmeters_and_aggregators(self, signed_lists):
    #     self.register_smartmeter, sm_sign, self.register_aggregator, agg_sign = signed_lists
        
    #     if not schnorr_verify_list(self.pk[0], self.pk[1], sm_sign, self.register_smartmeter):
    #         print("Smartmeters were not verified")
        
    #     if not schnorr_verify_list(self.pk[0], self.pk[1], agg_sign, self.register_aggregator):
    #         print("Aggregators were not verified")
    def publish_smartmeters_and_aggregators(self, signed_lists):
        self.register_smartmeter, sm_signatures, self.register_aggregator, agg_signatures = signed_lists

        sm_msg_list = [sm_id for sm_id, _ in self.register_smartmeter]
        agg_msg_list = [agg_id for agg_id, _ in self.register_aggregator]
        
        sm_valid, sm_results = schnorr_verify_list(self.pk[0], self.pk[1], sm_msg_list, sm_signatures)
        if not sm_valid:
            print("Smartmeters were not verified")
            for i, msg, is_valid in sm_results:
                if not is_valid:
                    print(f"Smartmeter ID {msg} at index {i} failed verification.")
            return False
        
        agg_valid, agg_results = schnorr_verify_list(self.pk[0], self.pk[1], agg_msg_list, agg_signatures)
        if not agg_valid:
            print("Aggregators were not verified")
            for i, msg, is_valid in agg_results:
                if not is_valid:
                    print(f"Aggregator ID {msg} at index {i} failed verification.")
            return False
        
        print("All smartmeters and aggregators were successfully verified.")
        return True

    def target_reduction(self, T_r):
        # the target reduction list is encrypted
        self.T_r = T_r

    # mix
    # def publish_mix_pk_and_proof(self, anon_id):
    #     anon_list = anon_id[0]
    #     πmix = anon_id[1]
        
    #     # shuffle proof verification is CheckProof
    #     if not CheckProof(πmix, self.register_smartmeter, anon_list, self.ek):
    #         print("Mixing proof verification failed")
        
    #     self.anon_id = anon_id
    # REPORT:
    # we had an issue here where we passed the entire self.register_smartmeter list which is (id, (pk, pp, proof)) to CheckProof
    # checkproof needs only the list of public keys (in the list e[]) to verify the shuffle proof
    # we use self.pk[1][1] as the generator g for the proof verification.
    # We use g because its a value both the prover and verifier agrees on, instead of a random pk from the list which may cause inconsistency
    # TODO should it really be g? its needed for the calculcation when making the challenge for both prover and verifier
    def publish_mix_pk_and_proof(self, mix_data):
        pk_prime, πmix = mix_data
        self.mix_pk = pk_prime
        self.mix_proof = πmix

        # store e list to verify
        # Extract the list of public keys from the registered smart meters list e
        # TODO change the name e 
        e = [sm[1][0] for sm in self.register_smartmeter]
        # The pk used for the proof generation should be consistent. We used the generator g.
        # self.pk[1][1] = g
        is_valid = CheckProof(πmix, e, pk_prime, self.pk[1][1])
        
        if is_valid:
            print("Mixing proof verification succeeded")

    # report
    # Should be sent through the anonym algorithm
    def publish_sm_reports(self, sm_reports):
        print(f"Publish anonym hashed reports on BB (not implemented)")
        self.sm_reports = sm_reports
        #[(pk, (t, cts, signature))] = sm_reports
        
        # pks = [report[0] for report in sm_reports]
        # msgs = [str((report[1][0], report[1][1])) for report in sm_reports]
        # signatures = [report[1][2] for report in sm_reports]

        # # pk, sec_params, msg_list, signatures
        # if not schnorr_verify_list(self.pk[0], self.pk[1], msgs, signatures):
        #     print("Smartmeters were not verified")
        
        # print("Published smartmeter reports:")
        # self.sm_reports = sm_reports










# import dso.DSO as dso
# import aggregators.aggregator as agg
# import smartmeters.smartmeter as smartmeter

# # DSO, users and aggregators with their public keys
# def make_registered_users_and_aggregators():
#     return dso.registration()

# # Get users from DSO
# dso_info, registered_users, registered_aggs = make_registered_users_and_aggregators()

# # DR parameters and target reduction
# def make_DRparam_and_targetreduction():
#     return dso.calculate_DR_param_and_target_reduction()

# # noisy list
# DSO_ek, DSO_dk = dso.create_encryption_key_set() # so that it can be given to all others
# reduction_target_list = dso.publish_reduction_target_list()
# smartmeter.get_DSO_ek(DSO_ek)

###################################################
# MIX Aggregator sends anon mixed pk set to board #
###################################################
# def publish_mixed_keys(pk_mixed, πmix):
#     print("Published mixed anonymized public keys:", pk_mixed)
#     print("Published proof of mixing (πmix):", πmix)

# # input for mixing
# ID_pk = [(agg_id, agg_val) for agg_id, agg_val in dict(registered_users).items()]

# # Use aggregator to mix and anonymize the keys
# pk_mixed, r_map, πmix = agg.create_mixed_anon_pk_set(ID_pk)

# # Board publishes the mixed keys and proof
# publish_mixed_keys(pk_mixed, πmix)

# # users get their anon keys from aggregators which is sent to the board
# smartmeter.get_anon_key()

# # get user reports and publish on board
# reports = agg.get_report_from_users()

# def publish_reports(reports):
#     print("=======================")
#     print("published user reports:")
#     print("len of reports: " + str(len(reports)))
#     for report in reports:
#         print(report)

# publish_reports(reports)

# # ===========
# # eval stuff
# # ===========
# ct_b = 100 # baseline report