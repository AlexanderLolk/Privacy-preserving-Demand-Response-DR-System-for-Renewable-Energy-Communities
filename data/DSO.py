# data/DSO.py
# The DSO works as a supplier in the system
# user's public keys
# DSO public key
# DR parameters (Demand Response)

# # parameters

# def send_dr_parameters():
#     dr_param = {
#         'p': "10%", 
#         "T_s": "1", 
#         "T_e": "22", 
#         "phi_star": "3.14$", 
#         'R': "x * 3.14", 
#         "belongsTo": "dead", 
#         "penalty_func": "x * (-2)"
#     }
#     return dr_param

# def send_target_reduction_val():
#     return 1000

#  SKeyGen(id, pp) to generate a signing key pair ((id, pk), sk) and publishes (id, pk) 
# pk = (pk, pp, proof)
# SkeyGen(id, pp) -> ((id, (pk, pp, proof)), sk)
# send to bb = (id, pk)

import utils.generators as gen
import utils.NIZKP as nizkp
import users.user as use

PP = (0, 0, 0)

def registration():
    registered = []
    pp = gen.pub_param()
    # signed keys
    ((id, (pk, pp, proof)), sk) = gen.skey_gen(pp)
    
    if nizkp.schnorr_NIZKP_verify(pp, pk, proof):
        print("DSO works")
    
    # verifies every smart meter
    user_info = use.get_user_signature(pp)
    
    for key, val in user_info.items():
        if nizkp.schnorr_NIZKP_verify(val[1], val[0], val[2]):
            registered.append((key, val))
            print("user: " + key + " is verified")
        else:
            print("failed mate")

    return registered

registration()