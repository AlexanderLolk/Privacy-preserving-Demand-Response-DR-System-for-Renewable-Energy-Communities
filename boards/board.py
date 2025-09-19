# this is both for public and private boards
from data.DSO import DSO_Supply, DSO_pk, DSO_user_public_keys, send_dr_parameters, send_target_reduction_val
import aggregators.energy as energy

# DSO public key
def get_DSO_public_key():
    return DSO_pk

# DSO user public keys
def get_DSO_user_public_keys():
    return DSO_user_public_keys

def get_DSO_DR_paramenters():
    return send_dr_parameters()

def get_DSO_target_reduction_value():
    return send_target_reduction_val()

# DSO user ID and public keys
def get_ENERGY_agg_id():
    return energy.get_user_ids()
