# data/DSO.py
# The DSO works as a supplier in the system
# user's public keys
# DSO public key
# DR parameters (Demand Response)
#       p (probability of selection)
#       T_s (start time of DR)
#       T_e (end time of DR)
#       π* (reward per unit reduction)
#       R(π∗, f, q) (reward function)
#       ∈ (deadband of omega Φ)
#       Φ(f − q) (penalty function)
# T_i (target reduction values)
import utils.params as params
from users.user import user_public_keys
 
# DSO parameters and key generation
DSO_p = params.prime_p()
DSO_g = params.generator_g(DSO_p)
DSO_sk = params.private_key(DSO_p)
DSO_A = params.computation_A(DSO_sk, DSO_p, DSO_g)
DSO_pk = params.public_key(DSO_p, DSO_g, DSO_A)

DSO_user_public_keys = user_public_keys

# parameters

def send_dr_parameters():
    dr_param = {
        'p': "10%", 
        "T_s": "1", 
        "T_e": "22", 
        "phi_star": "3.14$", 
        'R': "x * 3.14", 
        "belongsTo": "dead", 
        "penalty_func": "x * (-2)"
    }
    return dr_param

def send_target_reduction_val():
    return 1000