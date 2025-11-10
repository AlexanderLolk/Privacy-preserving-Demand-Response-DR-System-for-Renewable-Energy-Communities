# participating user
# non-participating user

import time
from utils.generators import pub_param, skey_gen, report
from utils.signature import schnorr_verify

class SmartMeter:
    
    def __init__(self, init_id="sm_id", pp=None):
        if pp is None:
           pp = pub_param()

        ((self.id, (self.pk, self.pp, self.s_proof)), self.sk) = skey_gen(init_id, pp)

    def get_public_key(self):
        return (self.pk, self.pp, self.s_proof)

    def set_dso_public_keys(self, dso_pk, dso_ek):
        self.dso_pk = dso_pk
        self.dso_ek = dso_ek

    def set_agg_public_keys(self, agg_pk):
        self.agg_pk = agg_pk

    # mix
    def set_anon_key(self, anon_key):
        (anon_pk, signature) = anon_key
        
        if not schnorr_verify(self, self.pp, signature):
            print("Anonymous key signature verification failed.")
        
        self.anon_pk = anon_pk

    # report
    # TODO: make sure m shouldnt be something else (placeholder right now)
    def generate_and_send_report(self):
        t = int(time.time())
        return report(self.id, self.sk, self.DSO_ek, m=10, t=t, user_pk=(self.pk, self.pp))
        




# import os
# import time
# import aggregators.aggregator as agg

# NUM_USERS = 3

# user_keys = []
# user_info = {} # dict, key is id and value is pk. id -> pk
# user_secret_keys = {}
# user_names = [] # not super important
# user_iden = [] 
# el_info = ()
# anon_key = []

# # TODO: Make all users as threads
# def make_user(pp):
#     base_dir = os.path.dirname(os.path.abspath(__file__))
#     names_path = os.path.join(base_dir, "../users/names.txt")

#     # user names and ids
#     with open(names_path, "r") as file:
#         for line in file:
#             words = line.strip().split()
#             ids = [word[0] for word in words if word]
#             ids = ids[0] + ". " + ids[1] 
#             user_names.append(line.strip())
#             user_iden.append(ids)

#     # user's public keys
#     for i in range(NUM_USERS):
#         user_id = user_iden[i]
#         ((id, (pk, pp, proof)), sk) = gen.skey_gen(pp)
#         verification = (pk, pp, proof)
#         user_info[user_id] = verification
#         user_secret_keys[user_id] = sk # secret key for report

#     return user_info

# def get_user_signature(pp):
#     mu = make_user(pp)
#     print(user_info["K. C"])
#     return mu

# ###############################################################
# # MIX, get r' from aggregator                                 #
# ###############################################################

# def get_anon_key():
#     global anon_key
#     anon_key = agg.publish_anon_key()

# ###############################################################
# # REPORT, user generate report and send it to aggregator      #
# ###############################################################

# DSO_ek = None
# def get_DSO_ek(ek):
#     global DSO_ek
#     DSO_ek = ek
    
# def generate_and_send_report():
#     t = int(time.time())
#     reports = []

#     for i in range(NUM_USERS):
#         user_id = user_iden[i]
#         sk = user_secret_keys[user_id]

#         # TODO randomize number of participating users?
#         # if else with non zero baseline
#         if i < NUM_USERS - 1: 
#             # participating user TODO
#             m = 10
#         else:
#             m = 0 # non-participating user sends 0 report

#         # gen.report Report(id, sk, ek, m, t) returns (pk, (t, ct, σ)) for each user
#         get_report = report(user_id, sk, DSO_ek, m, t, user_info)
#         reports.append(get_report)

#     return reports
    