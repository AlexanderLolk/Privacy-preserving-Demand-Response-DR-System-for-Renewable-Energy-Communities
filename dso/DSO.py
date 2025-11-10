# data/DSO.py
# The DSO works as a supplier in the system
# user's public keys
# DSO public key
# DR parameters (Demand Response)

# SKeyGen(id, pp) to generate a signing key pair ((id, pk), sk) and publishes (id, pk) 
# pk = (pk, pp, proof)
# SkeyGen(id, pp) -> ((id, (pk, pp, proof)), sk)
# send to bb = (id, pk)

from utils.generators import pub_param, skey_gen, ekey_gen
from utils.NIZKP import schnorr_NIZKP_verify
from utils.signature import schnorr_sign
from utils.ec_elgamal import enc
import random

class DSO:
    
    def __init__(self, init_id="DSO", pp=None):
        pp = pub_param()
        ((self.id, (self.pk, self.pp, self.s_proof)), self.sk) = skey_gen(init_id, pp)
        ((self.ek, _, self.e_proof), self.dk) = ekey_gen(init_id, pp)

    # verifies every smart meter (users)
    # and adds it into a registered list
    def verify_smartmeter(self, sm_info):
        self.registered_sm = []
        
        for sm_id, val in sm_info.items():
            # val = (pk, pp, proof) 
            if schnorr_NIZKP_verify(val[0], val[1], val[2]):
                self.registered_sm.append((sm_id, val))
                print("smart meter: " + sm_id + " is verified")
            else:
                print("failed to verify smart meter")
                return False
        return True
    
    # verifies every aggregator
    # and adds it into a registered list
    def verify_aggregator(self, agg_info):
        self.registered_agg = []
        
        for agg_id, val in agg_info.items():
            # val = (pk, pp, proof) 
            if schnorr_NIZKP_verify(val[0], val[1], val[2]):
                self.registered_agg.append((agg_id, val))
                print("aggregator: " + agg_id + " is verified")
            else:
                print("failed to verify aggregator")
                return False
        return True
    
    # DR parameters and target reductions
    def calculate_target_reduction():
        p = "1"
        phi = "0.05"
        R = "3"
        Ø = "4"
        E = "0.1"
        ts = "6"
        te = "7"
        delta_Q = "8"
        
        dr_param = [p, phi, R, Ø, E, ts, te, delta_Q]
        target_reduction_value = 2
        return dr_param, target_reduction_value

    # noisy list
    # TODO check if the noisy list is actually a mathematic implementation (this code was done as a translation of the report words)
    def generate_noisy_list(self):
        _, target_reduction = DSO.calculate_target_reduction()

        max_noise = max(1, target_reduction - 1)
        noise_count = random.randint(1, max_noise)
        zero_noise = random.randint(1, max_noise)

        values = [random.randint(0, target_reduction-1) for _ in range(noise_count)]
        values.append(target_reduction) 
        values += [0] * zero_noise
        random.shuffle(values)
        
        enc_TR = enc(self.pp, self.ek, values)
        
        return enc_TR

    def get_public_key(self):
        return (self.pk, self.pp, self.s_proof)
    
    def get_encryption_key(self):
        return (self.ek, self.pp, self.e_proof)
    
    # TODO MAY NOT WORK FOR LISTS
    def sign_registered_lists(self):
        sm_sign = schnorr_sign(self.sk, self.registered_sm)
        agg_sign = schnorr_sign(self.sk, self.registered_agg)
        return (self.registered_sm, sm_sign, self.registered_agg, agg_sign)



# import utils.generators as gen
# import utils.NIZKP as nizkp
# import utils.ec_elgamal as ahe
# import smartmeters.smartmeter as use
# import aggregators.aggregator as agg
# import random
    
# # ((ek, pp, πdk), dk)
# el_info = ()

# pp = ""

# # signed list of registered users
# def registration():
#     registered_users = []
#     registered_aggs = []
#     pp = gen.pub_param()
#     # signed keys
#     ((id, (pk, pp, proof)), sk) = gen.skey_gen(pp)
    
#     if nizkp.schnorr_NIZKP_verify(pp, pk, proof):
#         print("DSO works")
    
#     # verifies every smart meter
#     user_info = use.get_user_signature(pp)
#     if not (verify_user(user_info, registered_users, "user")):
#         return "User verification failed"
    
#     # verifies every aggregator
#     agg_info = agg.get_agg_signature(pp)
#     if not (verify_user(agg_info, registered_aggs, "aggregator")):
#         return "Aggregator verification failed"
    
#     # DSO information
#     dso_info = (id, (pk, pp, proof))
    
#     return (dso_info, registered_users, registered_aggs)

# # for board
# def create_encryption_key_set():
#     global el_info, pp
#     if pp == "" or pp is None:
#         pp = gen.pub_param()
#     if el_info == ():
#         el_info = gen.ekey_gen(pp)
#     return el_info[0] 

# # signed list of registered aggregators
# def verify_user(component_info, registered, component_type):
#     for key, val in component_info.items():
#         if nizkp.schnorr_NIZKP_verify(val[1], val[0], val[2]):
#             registered.append((key, val))
#             print(f"{component_type}: " + key + " is verified")
#         else:
#             print("failed")
#             return False
#     return True
 
# # DR param
# # - p, the probability of selecting a consumer for participation in the DR program (cfr. Equations 4 and 5). 
# # - π∗, the reward for unit reduction, which corresponds to the TMC price (e.g. $0.05/kWh, see Figure 2).
# # - R(π∗, f, q), the reward function (see Equation 1).
# # - Φ(f − q), the penalty function (see Equation 2).
# # - ϵ, deadband for deviations from self-reported baseline (e.g. 0.1 kWh, see Equation 2).
# # - Ts, start time of the DR event (e.g. 11:00 a.m.).
# # - Te, end time of the DR event (e.g. 1:00 p.m.).
# # Additionally, the DSO sends to the Aggregator the value ∆Q∗ (cfr. Figure 2), representing the load reduction target for the whole energy community in kWh/h.
# def calculate_DR_param_and_target_reduction():
#     p = "1"
#     phi = "0.05"
#     R = "3"
#     Ø = "4"
#     E = "0.1"
#     ts = "6"
#     te = "7"
#     delta_Q = "8"
    
#     dr_param = [p, phi, R, Ø, E, ts, te, delta_Q]
#     target_reduction_value = 2
#     return dr_param, target_reduction_value

# # noisy list
# def generate_reduction_target_list():
#     _, target_reduction = calculate_DR_param_and_target_reduction()

#     max_noise = max(1, target_reduction - 1)
#     noise_count = random.randint(1, max_noise)
#     zero_noise = random.randint(1, max_noise)

#     values = [random.randint(0, target_reduction-1) for _ in range(noise_count)]
#     values.append(target_reduction) 
#     values += [0] * zero_noise
#     random.shuffle(values)
    
#     return values

# # publish the noisy target list to BB using BB's public key
# def publish_reduction_target_list():
#     noisy_list = generate_reduction_target_list()
#     reduction_target_list = [ahe.enc(gen.pub_param(), el_info[0][0], val) for val in noisy_list]
#     return reduction_target_list

# # for agg
# def get_key_set():
#     global el_info, pp
#     if pp == "" or pp is None:
#         pp = gen.pub_param()
#     if el_info == ():
#         el_info = gen.ekey_gen(pp)
#     return (el_info[0][1], el_info[1])