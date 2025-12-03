# DR Aggregator
# The aggregator
import random
from utils.generators import ekey_gen_single, pub_param, skey_gen
from utils.signature import schnorr_sign
# from utils.ec_elgamal import ElGamal as ahe


class DR_Aggregator:
    """ """

    def __init__(self, init_id="dr_agg_id", pp=None):
        if pp is None:
            pp = pub_param()

        ((self.id, (self.pk, self.pp, self.s_proof)), self.sk) = skey_gen(init_id, pp)
        
        # TODO: do we need ek for the dr aggregator?
        ((self.ek, _, self.e_proof), self.dk) = ekey_gen_single(pp)
    
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
    
    def set_dso_dk(self, cipher_signature):
        """

        Args:
          cipher_signature: Bn
        
        """
        # print("[NOT IMP] In dr.set_dso_dk: got un-encrypted dso dk")
        # Some of the code what was tried on this function is in aggregator
        self.dso_dk = cipher_signature
    
    # anon_ids = pk_prime
    def set_psudo_anonymous_iden(self, anon_ids):
        """

        Args:
          anon_ids: list[EcPt]
        """
        self.anon_ids = anon_ids
    
    def select_random_sms(self):
        """ 

        """
        self.selected = random.sample(self.anon_ids, k=3)
    
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
    def get_partial_decryption_share(self, c1_point):
        return c1_point.pt_mul(self.sk_share)
    
    