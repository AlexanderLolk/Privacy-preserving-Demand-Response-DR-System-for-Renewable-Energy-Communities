import random
from utils.elgamal_dec_proof import prove_partial_decryption_share
from utils.procedures import Procedures

class DR_Aggregator:
    """ 
    Represents the Demand Response (DR) Aggregator.
    
    The DR Aggregator is responsible for:
     - Randomly selecting a subset of anonymized Smart Meters to participate in the event.
     - Holding a threshold decryption key share to ensure no single aggregator can
       decrypt the user data alone.
    """
    def __init__(self, init_id="dr_agg_id", pp=None):
        """
        Initializes the DR Aggregator.
        Generates signing keys and prepares to receive the decryption key share.
        """
        pro = Procedures()
        if pp is None:
            pp = pro.pub_param()

        ((self.id, (self.pk, self.pp, self.s_proof)), self.__sk) = pro.skey_gen(init_id, pp)
        ((self.ek, _, self.e_proof), self.__dk) = pro.ekey_gen_single(pp)

        self.dk_share = None
        self.thresh_params = None
        self.pro = pro
    
    def get_public_key(self):
        """Returns the DR Aggregator's signing public key package."""
        return (self.pk, self.pp, self.s_proof)
    
    def get_encryption_key(self):
        """Returns the Aggregator's own encryption key package."""
        return (self.ek, self.pp, self.e_proof)
    
    def get_dr_agg_id_And_encryption_key(self):
        """Returns ID and Encryption Key."""
        message_to_verify = self.id + str(self.ek.x) + str(self.ek.y)
        return (self.id, self.get_encryption_key(), self.pro.sig.schnorr_sign(self.__sk, self.pp, message_to_verify))

    def set_dso_public_keys(self, dso_pk, dso_ek):
        """
        Stores the DSO's public keys.
        
        Args:
          dso_pk: DSO Signing Key Package.
          dso_ek: System-wide Encryption Key Package.
        """
        self.dso_pk = dso_pk
        self.dso_ek = dso_ek
    
    def set_dso_dk(self, key_share):
        """
        Stores the Threshold Decryption Key Share assigned by the DSO.
        
        Args:
          key_share: The secret scalar share x_i.
        """
        from threshold_crypto import KeyShare
        x, enc_share, signature = key_share
        
        y = self.pro.ahe.dec(self.__dk, enc_share)
        if self.pro.sig.schnorr_verify(self.dso_pk[0], self.dso_pk[1], str((x, y)), signature) == False:
            raise ValueError("DSO signature verification on dk share failed")

        key_share = KeyShare(x, y, self.pp[0])

        self.dk_share = key_share
    
    # anon_ids = pk_prime
    def set_pseudo_anonymous_iden(self, anon_ids):
        """
        Receives the list of Anonymized Public Keys (pk') from the Board.
        These are the participants available for selection in the DR event.

        Args:
          anon_ids: list[pk'_i, ...]
        """
        self.anon_ids = anon_ids

    def get_participants(self):
        """Returns the list of all anonymized candidates."""
        return self.anon_ids
    
    def select_random_sms(self, k):
        """ 
        Randomly selects a subset of anonymized identities to participate in the event.
        """
        self.selected = random.sample(self.anon_ids, k)
    
    def get_selected(self):
        """ 
        Returns the list of selected participants, signed by the DR Aggregator.
        
        Returns:
            tuple: (Selected_List, Signature, DR_Agg_PK)
        """
        signature = self.pro.sig.schnorr_sign(self.__sk, self.pp, str(self.selected))
        
        return (self.selected, signature, self.get_public_key())
    
    def partial_dec_reports(self, baseline_BB, consumption_PBB):
        """
        Performs partial decryption on reports downloaded from the Board.
        
        Matches the logic in the Energy Aggregator (aggregator.py):
        - Iterates through all known participants.
        - Retrieves their Baseline and Consumption reports.
        - Computes partial decryption shares for both.

        Args:
          baseline_BB: Map of baseline reports.
          consumption_PBB: Map of consumption reports.

        Returns:
          tuple: (Baseline_Partial_Shares, Consumption_Partial_Shares)
        """
        baseline_pk_to_part = {}
        consumption_pk_to_part = {}

        for pk_prime in self.get_participants():
            pk_prime_str = str((pk_prime.x, pk_prime.y))

            # Process Baseline Report
            sm_baseline_t, sm_baseline_ct, sm_baseline_proof = baseline_BB[pk_prime_str]
            baseline_pk_to_part[pk_prime_str] = (
                self.pro.ahe.partial_decrypt(sm_baseline_ct, self.dk_share),
                sm_baseline_t,
                sm_baseline_proof
            )

            # Process Consumption Report
            sm_consumption_t, sm_consumption_ct, sm_consumption_proof = consumption_PBB[pk_prime_str]
            consumption_pk_to_part[pk_prime_str] = (
                self.pro.ahe.partial_decrypt(sm_consumption_ct, self.dk_share),
                sm_consumption_t,
                sm_consumption_proof
            )

        # for proof of correct decryption on one of the commitments
        pk_prime_commitment = self.get_participants()[0]
        pk_prime_commitment_str = str((pk_prime_commitment.x, pk_prime_commitment.y))
        _, commitment_ct, _ = baseline_BB[pk_prime_commitment_str] 
        proof = prove_partial_decryption_share(self.pp, commitment_ct[0], self.dk_share)

        return (baseline_pk_to_part, consumption_pk_to_part), (commitment_ct, proof)

    
    def partial_dec_equal_cts(self, equal_cts):
        """
        Helper function to partially decrypt a list of specific ciphertexts.
        Used for verification of the Noisy List or other specific data sets.
        """
        partial_cts = []
        for ct in equal_cts:
            partial_ct = self.pro.ahe.partial_decrypt(ct, self.dk_share)
            partial_cts.append(partial_ct)
        return partial_cts