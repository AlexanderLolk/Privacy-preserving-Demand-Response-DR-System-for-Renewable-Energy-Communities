# this is both for public and private boards
import data.DSO as DSO
import aggregators.energy as energy

# DSO public key
def get_DSO_public_key():
    return DSO.DSO_pk

# DSO user public keys
def get_DSO_user_public_keys():
    return DSO.DSO_user_public_keys

def get_DSO_DR_paramenters():
    return DSO.send_dr_parameters()

def get_DSO_target_reduction_value():
    return DSO.send_target_reduction_val()

# DSO user ID and public keys
def get_ENERGY_agg_id():
    return energy.get_user_ids()
