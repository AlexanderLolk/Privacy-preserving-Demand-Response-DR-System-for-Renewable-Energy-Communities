# this is both for public and private boards
from data.DSO import DSO_Supply, DSO_pk, DSO_user_public_keys


# test msg
def get_DSO_supply():
    return DSO_Supply

# DSO public key
def get_DSO_public_key():
    return DSO_pk

# DSO user public keys
def get_DSO_user_public_keys():
    return DSO_user_public_keys

