# data/DSO.py
# The DSO works as a supplier in the system
# user's public keys
# DSO public key
# DR parameters (Demand Response)

from utils.generators import pub_param, skey_gen, ekey_gen
from utils.NIZKP import schnorr_NIZKP_verify
from utils.signature import schnorr_sign_list, schnorr_sign
from utils.ec_elgamal import enc
import random

class DSO:
    
    def __init__(self, init_id="DSO", pp=None):
        pp = pub_param()
        self.registered_sm = []
        self.registered_agg = []
        self.registered_dr = []
        
        #  SkeyGen(id, pp) -> ((id, (pk, pp, proof)), sk)
        ((self.id, (self.pk, self.pp, self.s_proof)), self.sk) = skey_gen(init_id, pp)
        ((self.ek, _, self.e_proof), self.dk) = ekey_gen(pp)

    # verifies every smart meter (users)
    # and adds it into a registered list
    def verify_smartmeter(self, sm_info):
        sm_id, val = sm_info
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
        agg_id, val = agg_info
        # val = (pk, pp, proof)
        if schnorr_NIZKP_verify(val[0], val[1], val[2]):
            self.registered_agg.append((agg_id, val))
            print("aggregator: " + agg_id + " is verified")
        else:
            print("failed to verify aggregator")
            return False
        return True
    
    def verify_dr_aggregator(self, dr_info):
        dr_id, val = dr_info
        # val = (pk, pp, proof) 
        if schnorr_NIZKP_verify(val[0], val[1], val[2]):
            self.registered_dr.append((dr_id, val))
            print("aggregator: " + dr_id + " is verified")
        else:
            print("failed to verify aggregator")
            return False
        return True
    
    # DR parameters and target reductions
    # Placeholder values for now
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
        
        # encrypt each value in the noisy list and then sign the list
        # TODO should it be each value thats signed or is signing the entire list ok?
        enc_TR = [enc(self.ek, self.pp, val) for val in values]
        signature_TR = schnorr_sign(self.sk, self.pp, str(enc_TR))

        return enc_TR, signature_TR

    def get_public_key(self):
        return (self.pk, self.pp, self.s_proof)
    
    def get_encryption_key(self):
        return (self.ek, self.pp, self.e_proof)
    
    def set_agg_encryption_key(self, aggs):
        # aggs = [(id, ek)]
        self.agg_ek = {id: ek for (id, ek) in aggs}    

    # Report: encrypting isn't implemented
    # This should use secure channels over SSL in production
    def encrypt_dk_and_send_to_agg(self, agg_id):
        print("[NOT IMP] In dso.encrypt_dk_and_send_to_agg: un-encrypted dso dk given to agg (supposed to be a private channel over SSL)")
        return self.dk
        
        # ek = self.agg_ek.get(agg_id)
        # print("for agg id: ", agg_id)
        # print("DSO decrypting key: ", str(self.dk))

        # # Sign the point representation of dk (so verifier and signer use same canonical form)
        # # self.pp is (G, g, o) so g is self.pp[1]
        # dk_point = self.pp[1].pt_mul(self.dk)
        # sign_dk = schnorr_sign(self.sk, self.pp, msg=str(dk_point))
        
        # enc_dk = enc(ek, self.pp, self.dk)
        
        # return (enc_dk, sign_dk)

    def sign_registered_lists(self):
        sm_msg_list = [sm_id for sm_id, _ in self.registered_sm]
        agg_msg_list = [agg_id for agg_id, _ in self.registered_agg]
        dr_msg_list = [dr_id for dr_id, _ in self.registered_dr]

        # (sk, sec_params, msg_list)
        sm_signatures = schnorr_sign_list(self.sk, self.pp, sm_msg_list)
        agg_signatures = schnorr_sign_list(self.sk, self.pp, agg_msg_list)
        dr_signatures = schnorr_sign_list(self.sk, self.pp, dr_msg_list)

        return (self.registered_sm, sm_signatures, self.registered_agg, agg_signatures, self.registered_dr, dr_signatures)