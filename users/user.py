# participating user
# non-participating user

import utils.generators as gen
import os 

NUM_USERS = 3

user_keys = []
user_info = {}
user_names = []
user_iden = []

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
    return user_info

def get_user_signature(pp):
    return make_user(pp)