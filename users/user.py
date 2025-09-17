# participating user
# non-participating user
# aggregator anonymizes key send its back to keep track of users

import utils.params as params

NUM_USERS = 3

# parameters
largeprime_p = params.prime_p()
generator_g = params.generator_g()
user_keys = []

# user's public keys
for _ in range(NUM_USERS):
    user_sk = params.private_key()
    user_A = params.computation_A(user_sk, largeprime_p, generator_g)
    user_pk = params.public_key(largeprime_p, generator_g, user_A)
    user_keys.append({'public key': user_pk})

user_public_keys = [user_keys[i]['public key'] for i in range(NUM_USERS)]