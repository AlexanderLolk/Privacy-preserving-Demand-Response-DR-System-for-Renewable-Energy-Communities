# data/DSO.py
# The DSO works as a supplier in the system
# user's public keys
# DSO public key
# DR parameters (malicious aggregator)
# T_i (target reduction values)
from utils.params import public_key
from users.user import user_public_keys

# DSO parameters and key generation
DSO_pk = public_key()
DSO_user_public_keys = user_public_keys

# example int that goes from DSO to board, then main can print it
DSO_Supply = 1000