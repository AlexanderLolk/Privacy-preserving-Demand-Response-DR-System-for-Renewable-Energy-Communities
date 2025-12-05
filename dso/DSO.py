# data/DSO.py
# The DSO works as a supplier in the system
# user's public keys
# DSO public key
# DR parameters (Demand Response)

from utils.procedures import Procedures
from utils.NIZKP import schnorr_NIZKP_verify
from utils.signature import schnorr_sign_list, schnorr_sign
from utils.ec_elgamal import ElGamal
import random

class DSO:
    """ """
    
    def __init__(self, init_id="DSO", pp=None):
        self.pro = Procedures()
        pp = self.pro.pub_param()
        self.registered_sm = []
        self.registered_agg = []
        self.registered_dr = []
        
        #  SkeyGen(id, pp) -> ((id, (pk, pp, proof)), sk)
        ((self.id, (self.pk, self.pp, self.s_proof)), self.sk) = self.pro.skey_gen(init_id, pp)
        ((self.ek, self.thresh_params, self.e_proof), self.key_shares) = self.pro.ekey_gen(pp)
        self.i = 0

    def get_threshold_params(self):
        """Return the threshold parameters for decryption."""
        return self.thresh_params
    
    # verifies every smart meter (users)
    # and adds it into a registered list
    def verify_smartmeter(self, sm_info):
        """Verifies a smartmeter by checking Schnorr's NIZKP.
        If the NIZKP is valid, the smartmeter is added to the list of registered smartmeters.

        Args:
            - sm_info (tuple[str, tuple[EcPt, tuple[EcGroup, EcPt, Bn], tuple[Bn, Bn, EcPt]]]):
                A tuple containing the smartmeter's information:
                - sm_info[0] (str): The identity (ID) of the smartmeter.
                - sm_info[1] (tuple): Cryptographic parameters:
                    - sm_info[1][0] (EcPt): Public signature key (pk).
                    - sm_info[1][1] (tuple): Public parameters (G, g, order).
                    - sm_info[1][2] (tuple): Schnorr NIZKP proof (challenge, response, commitment)

        Returns:
            bool: False if the verification (Schnorr's NIZKP check) fails, 
            if true then a the smartmeter to a list registered smartmeters 
        """

        sm_id, val = sm_info
        # val = (pk, pp, proof)
        if schnorr_NIZKP_verify(val[0], val[1], val[2]):
            self.registered_sm.append((sm_id, val))
            # print("smart meter: " + sm_id + " is verified")
        else:
            print("failed to verify smart meter")
            return False
    
    # verifies every aggregator
    # and adds it into a registered list
    def verify_aggregator(self, agg_info):
        """Verifies a aggregator by checking Schnorr's NIZKP.
        If the NIZKP is valid, the aggregator is added to the list of registered aggregators.

        Args:
            - agg_info (tuple[str, tuple[EcPt, tuple[EcGroup, EcPt, Bn], tuple[Bn, Bn, EcPt]]]):
                A tuple containing the aggregator's information:
                - agg_info[0] (str): The identity (ID) of the aggregator.
                - agg_info[1] (tuple): Cryptographic parameters:
                    - agg_info[1][0] (EcPt): Public signature key (pk).
                    - agg_info[1][1] (tuple): Public parameters (G, g, order).
                    - agg_info[1][2] (tuple): Schnorr NIZKP proof (challenge, response, commitment)

        Returns:
            bool: False if the verification (Schnorr's NIZKP check) fails. 
        """
        agg_id, val = agg_info
        # val = (pk, pp, proof)
        if schnorr_NIZKP_verify(val[0], val[1], val[2]):
            self.registered_agg.append((agg_id, val))
            # print("aggregator: " + agg_id + " is verified")
        else:
            print("failed to verify aggregator")
            return False
    
    def verify_dr_aggregator(self, dr_info):
        """Verifies a dr aggregator by checking Schnorr's NIZKP.
        If the NIZKP is valid, the aggregator is added to the list of registered dr aggregators.

        Args:
            - agg_info (tuple[str, tuple[EcPt, tuple[EcGroup, EcPt, Bn], tuple[Bn, Bn, EcPt]]]):
                A tuple containing the dr aggregator's information:
                - agg_info[0] (str): The identity (ID) of the dr aggregator.
                - agg_info[1] (tuple): Cryptographic parameters:
                    - agg_info[1][0] (EcPt): Public signature key (pk).
                    - agg_info[1][1] (tuple): Public parameters (G, g, order).
                    - agg_info[1][2] (tuple): Schnorr NIZKP proof (challenge, response, commitment)

        Returns:
            bool: False if the verification (Schnorr's NIZKP check) fails. 
        """
        dr_id, val = dr_info
        # val = (pk, pp, proof) 
        if schnorr_NIZKP_verify(val[0], val[1], val[2]):
            self.registered_dr.append((dr_id, val))
            # print("aggregator: " + dr_id + " is verified")
        else:
            print("failed to verify aggregator")
            return False
    
    # DR parameters and target reductions
    # Placeholder values for now
    def calculate_target_reduction():
        """ 
        Returns:
            tuple[tuple[EcGroup, EcPt, Bn], int]: 
        """
        p = "1"
        phi = "0.05"
        R = "3"
        Ø = "4"
        E = "0.1"
        ts = "6"
        te = "7"
        delta_Q = "8"
        
        dr_param = [p, phi, R, Ø, E, ts, te, delta_Q]
        target_reduction_value = 310
        return dr_param, target_reduction_value

    # noisy list
    # TODO check if the noisy list is actually a mathematic implementation (this code was done as a translation of the report words)
    def generate_noisy_list(self):
        """ 
        Returns:
            tuple[list[EcPt, EcPt], tuple[EcPt, Bn]]: some explanantion
        """
        _, target_reduction = DSO.calculate_target_reduction()

        max_noise = max(1, target_reduction - 1)
        noise_count = random.randint(1, max_noise)
        zero_noise = random.randint(1, max_noise)

        values = [random.randint(0, target_reduction-1) for _ in range(noise_count)]
        # print("\n ")
        # print("noisy list before tr insert: " + str(values) + "\n")
        values.append(target_reduction) 
        # print("noisy list -> appended tr: " + str(values) + "\n")
        values += [0] * zero_noise
        # print("noisy list -> after adding zero_noise tr: " + str(values) + "\n")
        random.shuffle(values)
        # print("noisy list -> after shuffle: " + str(values) + "\n")

        # ek is a tuple: (curve, g, order, pk_point), extract pk_point
        # if isinstance(self.ek, tuple):
        #     _, _, _, pk_point = self.ek
        # else:
        #     pk_point = self.ek
        
        # encrypt each value in the noisy list and then sign the list
        # TODO should it be each value thats signed or is signing the entire list ok?
        enc_TR = [self.pro.ahe.enc(self.ek, val) for val in values]
        # enc_TR = [self.pro.ahe.enc(self.ek, val)[0] for val in values]
        # enc_TR = [self.pro.ahe.encrypt_single(self.ek, val) for val in values]
        signature_TR = schnorr_sign(self.sk, self.pp, str(enc_TR))

        return enc_TR, signature_TR

    def get_public_key(self):
        """ 
        Returns:
            tuple[EcPt, tuple[EcGroup, EcPt, Bn], tuple[Bn, Bn, EcPt]]:
            some explanantion
        """
        return (self.pk, self.pp, self.s_proof)
    
    def get_encryption_key(self):
        """ 
        Returns:
            tuple[EcPt, tuple[EcGroup, EcPt, Bn], tuple[EcPt, tuple[EcPt, EcPt], tuple[EcPt, EcPt], Bn]]: 
            some explanantion
        """
        return (self.ek, self.pp, self.e_proof)
    
    def set_agg_encryption_key(self, aggs):
        """

        Args:
            - aggs (tuple[str, tuple[EcPt, tuple[EcGroup, EcPt, Bn], tuple[EcPt, tuple[EcPt, EcPt], tuple[EcPt, EcPt], Bn]]]) 

        """

        # aggs = [(id, ek)]
        self.agg_ek = {id: ek for (id, ek) in aggs}    

    # Report: encrypting isn't implemented
    # This should use secure channels over SSL in production
    def encrypt_dk_and_send_to_agg(self, agg_id):
        """

        Args:
            - agg_id: (str): 

        """
        print("[NOT IMP] In dso.encrypt_dk_and_send_to_agg: un-encrypted dso dk given to agg (supposed to be a private channel over SSL)")
        #TODO kinda stupid, make better
        key_share = self.key_shares[self.i]
        self.i = self.i + 1
        return key_share
        
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
        """
        returns:
            tuple[list[(str, tuple[EcPt, tuple[EcGroup, EcPt, Bn], tuple[Bn, Bn, EcPt]])], tuple[EcPt, Bn],
            list[(str, tuple[EcPt, tuple[EcGroup, EcPt, Bn], tuple[Bn, Bn, EcPt]])], tuple[EcPt, Bn],
            list[(str, tuple[EcPt, tuple[EcGroup, EcPt, Bn], tuple[Bn, Bn, EcPt]])], tuple[EcPt, Bn]]
        """
        sm_msg_list = [sm_id for sm_id, _ in self.registered_sm]
        agg_msg_list = [agg_id for agg_id, _ in self.registered_agg]
        dr_msg_list = [dr_id for dr_id, _ in self.registered_dr]

        # (sk, sec_params, msg_list)
        sm_signatures = schnorr_sign_list(self.sk, self.pp, sm_msg_list)
        agg_signatures = schnorr_sign_list(self.sk, self.pp, agg_msg_list)
        dr_signatures = schnorr_sign_list(self.sk, self.pp, dr_msg_list)

        return (self.registered_sm, sm_signatures, self.registered_agg, agg_signatures, self.registered_dr, dr_signatures)