# DR Aggregator
# The aggregator
import random
from utils.procedures import Procedures
from utils.signature import schnorr_sign
# from utils.ec_elgamal import ElGamal as ahe


class DR_Aggregator:
    """ """

    def __init__(self, init_id="dr_agg_id", pp=None):
        pro = Procedures()
        if pp is None:
            pp = pro.pub_param()

        ((self.id, (self.pk, self.pp, self.s_proof)), self.sk) = pro.skey_gen(init_id, pp)
        
        # TODO: do we need ek for the dr aggregator?
        ((self.ek, _, self.e_proof), self.dk) = pro.ekey_gen_single(pp)

        self.dk_share = None
        self.thresh_params = None
        self.pro = pro
    
    def get_public_key(self):
        """ 
        return: 
            tuple[EcPt, tuple[EcGroup, EcPt, Bn], tuple[Bn, Bn, EcPt]]
        """
        return (self.pk, self.pp, self.s_proof)

    def set_dso_public_keys(self, dso_pk, dso_ek):
        """

        Args:
          dso_pk: tuple[EcPt, tuple[EcGroup, EcPt, Bn], tuple[Bn, Bn, EcPt]]
          dso_ek: tuple[EcPt, tuple[EcGroup, EcPt, Bn], tuple[EcPt, tuple[EcPt, EcPt], tuple[EcPt, EcPt], Bn]]

        """
        self.dso_pk = dso_pk
        self.dso_ek = dso_ek
    
    def set_dso_dk(self, key_share):
        """

        Args:
          cipher_signature: Bn
        
        """
        # print("[NOT IMP] In dr.set_dso_dk: got un-encrypted dso dk")
        # Some of the code what was tried on this function is in aggregator
        # self.dso_dk = cipher_signature
        self.dk_share = key_share
    
    # anon_ids = pk_prime
    def set_psudo_anonymous_iden(self, anon_ids):
        """

        Args:
          anon_ids: list[EcPt]
        """
        self.anon_ids = anon_ids

    def get_participants(self):
        return self.anon_ids
    
    def select_random_sms(self):
        """ 

        """
        self.selected = random.sample(self.anon_ids, k=2)
    
    # TODO if this need to be signed, then give pk before this function
    def get_selected(self):
        """ 
        return:
            tuple[list[EcPt], tuple[Bn, Bn, EcPt], tuple[EcPt, tuple[EcGroup, EcPt, Bn], tuple[Bn, Bn, EcPt]]]
        """
        signature = schnorr_sign(self.sk, self.pp, str(self.selected))
        return (self.selected, signature, self.get_public_key())

    def set_anonym_reports(self):
        """ 
        TODO
        """
        return None
    
    #partial decryption
    def get_partial_decryption_share(self, ciphertexts):
        # return c1_point.pt_mul(self.sk_share)
        return self.pro.ahe.partial_decrypt(ciphertexts, self.dk_share)
    
    def partial_dec_reports(self, baseline_BB, consumption_PBB):
        baseline_pk_to_part = {}
        consumption_pk_to_part = {}
        # baseline_part = []
        # consumption_part = []
        # print(f"\n\n\n in dr, len of get_participants = {len(self.get_participants())}\n\n\n")
        for pk_prime in self.get_participants():
            pk_prime_str = str((pk_prime.x, pk_prime.y))
            # baseline_BB[pk_prime] = (ct, t, proof)
            sm_baseline_t, sm_baseline_ct, sm_baseline_proof = baseline_BB[pk_prime_str]
            # baseline_part.append((pk_prime, self.pro.ahe.partial_decrypt(sm_baseline_ct, self.dk_share), sm_baseline_t, sm_baseline_proof))
            baseline_pk_to_part[pk_prime_str] = (self.pro.ahe.partial_decrypt(sm_baseline_ct, self.dk_share), sm_baseline_t, sm_baseline_proof)

            # baseline_BB[pk_prime] = (ct, t, proof)
            sm_consumption_t, sm_consumption_ct, sm_consumption_proof = consumption_PBB[pk_prime_str]
            # consumption_part.append((pk_prime, self.pro.ahe.partial_decrypt(sm_consumption_ct, self.dk_share), sm_consumption_t, sm_consumption_proof))
            consumption_pk_to_part[pk_prime_str] = (self.pro.ahe.partial_decrypt(sm_consumption_ct, self.dk_share), sm_consumption_t, sm_consumption_proof)

        return (baseline_pk_to_part, consumption_pk_to_part)