# participating user
# non-participating user

import utils.generators as gen
import os 
from datetime import datetime
import utils.generators as gen
import aggregators.aggregator as agg

NUM_USERS = 3

user_keys = []
user_info = {}
user_names = []
user_iden = []
el_info = ()

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

    for i in range(NUM_USERS):
        user_id = user_iden[i]
        ((ek, pp, πdk), dk) = gen.ekey_gen(pp)

    return user_info

def establish_secure_connection():
    # ((ek, pp, πdk), dk)
    if el_info == ():
        el_info = gen.ekey_gen(user_info[0][1])
    
    return el_info[0][0]

def get_user_signature(pp):
    mu = make_user(pp)
    print(user_info["K. C"])
    return mu

# def report_baseline():
#     timestamp = datetime.now()    
#     for user in user_info:
#         gen.report(self, user[1], timestamp)
        
# for user in user_info:

# print(user_info["K. C"])

###############################################################
# MIX, get r' from aggregator                                 #
###############################################################
user_randomizations = {}

def receive_randomization(user_id, r_val):
    user_randomizations[user_id] = r_val
    print(f"User {user_id} received randomization r′: {r_val}")


###############################################################
# MIX, testing receive_randomization                          #
###############################################################
pp = gen.pub_param()

# Get registered users and aggregators
user_info = make_user(pp)  # from user.py
agg_info = agg.make_aggregator(pp)  # from aggregator.py

# Prepare input for mixing
ID_pk = [(agg_id, agg_val) for agg_id, agg_val in agg_info.items()]

# Run mixing to get r_map
pk_mixed, r_map, proofs, πmix = agg.create_mixed_anon_pk_set(ID_pk)

# test the users receive their r'
for user_id, r_val in r_map.items():
    receive_randomization(user_id, r_val)

print("User randomizations:", user_randomizations)