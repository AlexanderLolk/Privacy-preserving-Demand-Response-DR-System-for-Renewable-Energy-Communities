# data/DSO.py
# The DSO works as a supplier in the system
# user's public keys
# DSO public key
# DR parameters (malicious aggregator)
# T_i (target reduction values)
from utils.params import prime_p, generator_g, private_key, computation_A, public_key
from users.user import user_public_keys

# DSO parameters and key generation
DSO_p = prime_p()
DSO_g = generator_g()
DSO_sk = private_key()
DSO_A = computation_A(DSO_sk, DSO_p, DSO_g)
DSO_pk = public_key(DSO_p, DSO_g, DSO_A)

DSO_user_public_keys = user_public_keys

# example int that goes from DSO to board, then main can print it
DSO_Supply = 1000