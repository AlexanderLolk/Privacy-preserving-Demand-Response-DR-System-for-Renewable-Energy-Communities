# this is both for public and private boards
from utils.signature import schnorr_verify
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
        
        # TODO: fix 
        if not verify_correct_decryption(ek, pp, e_proof):
            print("DSO encryption key proof verification failed")
        
        self.pk, self.ek = dso_keys
        
    # The DSO registers and has verified users and aggregators, then sends it to the board
    # TODO rewrite all schnorr_verify name to be schnorr_sign_verify for clarity
    # TODO REFACTOR TO WORK FOR LISTS
    def publish_smartmeters_and_aggregators(self, signed_lists):
        self.register_smartmeter, sm_sign, self.register_aggregator, agg_sign = signed_lists
        
        if not schnorr_verify(self.pk[0], self.pk[1], sm_sign, self.register_smartmeter):
            print("Smartmeters were not verified")
        
        if not schnorr_verify(self.pk[0], self.pk[1], agg_sign, self.register_aggregator):
            print("Aggregators were not verified")


    def target_reduction(self, T_r):
        # the target reduction list is encrypted
        self.T_r = T_r

    # mix
    def publish_anonymized_keys(self, anon_id):
        anon_list = anon_id[0]
        πmix = anon_id[1]
        
        # shuffle proof verification is CheckProof
        if not CheckProof(πmix, self.register_smartmeter, anon_list, self.ek):
            print("Mixing proof verification failed")
        
        self.anon_id = anon_id

    # report
    def publish_sm_reports(self, sm_reports):
        
        # TODO REFACTOR TO WORK FOR LISTS
        if not schnorr_verify(self.pk[0], self.pk[1]):
            print("Smartmeters were not verified")
        
        print("Published smartmeter reports:")
        self.sm_reports = sm_reports










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