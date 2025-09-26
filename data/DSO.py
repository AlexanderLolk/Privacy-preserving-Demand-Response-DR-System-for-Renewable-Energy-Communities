# data/DSO.py
# The DSO works as a supplier in the system
# user's public keys
# DSO public key
# DR parameters (Demand Response)

# SKeyGen(id, pp) to generate a signing key pair ((id, pk), sk) and publishes (id, pk) 
# pk = (pk, pp, proof)
# SkeyGen(id, pp) -> ((id, (pk, pp, proof)), sk)
# send to bb = (id, pk)

import utils.generators as gen
import utils.NIZKP as nizkp
import users.user as use
import aggregators.aggregator as agg

# signed list of registered users
def registration():
    registered_users = []
    registered_aggs = []
    pp = gen.pub_param()
    # signed keys
    ((id, (pk, pp, proof)), sk) = gen.skey_gen(pp)
    
    if nizkp.schnorr_NIZKP_verify(pp, pk, proof):
        print("DSO works")
    
    # verifies every smart meter
    user_info = use.get_user_signature(pp)
    if not (verify_agg_user(user_info, registered_users, "user")):
        return "failed"
    
    # verifies every aggregator
    agg_info = agg.get_agg_signature(pp)
    if not (verify_agg_user(agg_info, registered_aggs, "aggregator")):
        return "failed"
    
    return (registered_users, registered_aggs)

# signed list of registered aggregators
def verify_agg_user(component_info, registered, component_type):
    for key, val in component_info.items():
        if nizkp.schnorr_NIZKP_verify(val[1], val[0], val[2]):
            registered.append((key, val))
            print(f"{component_type}: " + key + " is verified")
        else:
            print("failed")
            return False
    return True
