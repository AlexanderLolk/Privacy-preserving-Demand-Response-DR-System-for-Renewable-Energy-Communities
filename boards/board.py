# this is both for public and private boards
import data.DSO as dso
import utils.ec_elgamal as ahe
import utils.generators as gen
import aggregators.aggregator as agg

# noisy list
board_pk, board_sk = ahe.key_gen(gen.pub_param())
reduction_target_list = dso.publish_reduction_target_list(board_pk)
el_info = ()

def establish_secure_connection():
    # ((ek, pp, πdk), dk)
    if el_info == ():
        el_info = gen.ekey_gen(gen.pp)
    
    return el_info[0][0]

# DSO, users and aggregators with their public keys
def make_registered_users_and_aggregators():
    return dso.registration()

def make_DRparam_and_targetreduction():
    return dso.calculate_DR_param_and_target_reduction()

def get_registered_users():
    return registered_users

# dso_info, registered_users, registered_aggs = make_registered_users_and_aggregators()

#print(registered_users)

###################################################
# MIX Aggregator sends anon mixed pk set to board #
###################################################
def publish_mixed_keys(pk_mixed, πmix):
    print("Published mixed anonymized public keys:", pk_mixed)
    print("Published proof of mixing (πmix):", πmix)

# Get users from DSO
dso_info, registered_users, registered_aggs = make_registered_users_and_aggregators()

# input for mixing
ID_pk = [(agg_id, agg_val) for agg_id, agg_val in dict(registered_aggs).items()]

# Use aggregator to mix and anonymize the keys
pk_mixed, r_map, proofs, πmix = agg.create_mixed_anon_pk_set(ID_pk)

# Board publishes the mixed keys and proof
publish_mixed_keys(pk_mixed, πmix)