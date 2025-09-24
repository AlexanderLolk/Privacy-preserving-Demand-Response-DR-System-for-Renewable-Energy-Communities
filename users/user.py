# participating user
# non-participating user
# aggregator anonymizes key send its back to keep track of users

import utils.params as params
import os 


NUM_USERS = 3

# parameters
largeprime_p = params.prime_p()
generator_g = params.generator_g(largeprime_p)
user_keys = []

user_names = []
user_iden = []
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
    user_sk = params.private_key(largeprime_p)
    user_A = params.computation_A(user_sk, largeprime_p, generator_g)
    user_pk = params.public_key(largeprime_p, generator_g, user_A)
    user_keys.append({user_pk})

user_public_keys = [user_keys[i] for i in range(NUM_USERS)]
user_ids = [user_iden[i] for i in range(NUM_USERS)]