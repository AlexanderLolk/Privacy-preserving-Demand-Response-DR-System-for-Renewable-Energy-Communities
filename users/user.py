# participating user
# non-participating user

import os
import time
import utils.generators as gen
import aggregators.aggregator as agg

NUM_USERS = 3

user_keys = []
user_info = {} # dict, key is id and value is pk. id -> pk
user_secret_keys = {}
user_names = [] # not super important
user_iden = [] 
el_info = ()
anon_key = []

# TODO: Make all users as threads
def make_user(pp):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    names_path = os.path.join(base_dir, "../users/names.txt")

    # user names and ids
    with open(names_path, "r") as file:
        for line in file:
            words = line.strip().split()
            ids = [word[0] for word in words if word]
            ids = ids[0] + ". " + ids[1] 
            user_names.append(line.strip())
            user_iden.append(ids)

    # user's public keys
    for i in range(NUM_USERS):
        user_id = user_iden[i]
        ((id, (pk, pp, proof)), sk) = gen.skey_gen(pp)
        verification = (pk, pp, proof)
        user_info[user_id] = verification
        user_secret_keys[user_id] = sk # secret key for report

    return user_info

def get_user_signature(pp):
    mu = make_user(pp)
    print(user_info["K. C"])
    return mu

###############################################################
# MIX, get r' from aggregator                                 #
###############################################################

def get_anon_key():
    global anon_key
    anon_key = agg.publish_anon_key()

###############################################################
# REPORT, user generate report and send it to aggregator      #
###############################################################

DSO_ek = None
def get_DSO_ek(ek):
    global DSO_ek
    DSO_ek = ek
    
def generate_and_send_report():
    t = int(time.time())
    reports = []

    for i in range(NUM_USERS):
        user_id = user_iden[i]
        sk = user_secret_keys[user_id]

        # TODO randomize number of participating users?
        # if else with non zero baseline
        if i < NUM_USERS - 1: 
            # participating user TODO
            m = 10
        else:
            m = 0 # non-participating user sends 0 report

        # gen.report Report(id, sk, ek, m, t) returns (pk, (t, ct, σ)) for each user
        report = gen.report(user_id, sk, DSO_ek, m, t, user_info)
        reports.append(report)

    return reports
    