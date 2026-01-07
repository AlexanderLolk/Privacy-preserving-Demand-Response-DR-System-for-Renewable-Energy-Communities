import time
import random
from src.utils.elgamal_dec_proof import verify_correct_decryption
from src.utils.procedures import Procedures


class SmartMeter:
    """ 
    Represents a Smart Meter (user).
    
    The Smart Meter (SM) is responsible for:
     - generating its own identity keys.
     - receiving necessary keys from the DSO (Distribution System Operator) and Aggregator.
     - verifying its anonymized identity assignment.
     - generating signed, encrypted reports of energy consumption/reduction.
    """
    def __init__(self, init_id="sm_id", pp=None):
        self.pro = Procedures()
        
        if pp is None:
           pp = self.pro.pub_param()

        # Generate signing key pair and proof of ownership
        ((self.id, (self.pk, self.pp, self.s_proof)), self.__sk) = self.pro.skey_gen(init_id, pp)
        ((self.ek, _, self.e_proof), self.__dk) = self.pro.ekey_gen_single(pp)
        
        # as a default
        self.participating = False

    def get_public_key(self):
        """
        Retrieves the Smart Meter's public key package.

        Returns:
            tuple: (Public_Key_Point, Public_Params, Proof_of_Knowledge)
        """
        return (self.pk, self.pp, self.s_proof)
    
    def get_encryption_key(self):
        """Returns the smart meter's own encryption key package."""
        return (self.ek, self.pp, self.e_proof)

    def set_dso_public_keys(self, dso_pk, dso_ek):
        """
        Stores the Distribution System Operator's keys.
        These are needed to encrypt reports destined for the DSO.

        Args:
            dso_pk (tuple): The DSO's signing public key structure.
            dso_ek (tuple): The DSO's ElGamal encryption key structure 
                            (includes the Public Key Point and Threshold Params).
        """
        self.dso_pk = dso_pk
        self.dso_ek = dso_ek

    def set_agg_public_keys(self, agg_pk):
        """
        Stores the Aggregator's public key.
        This is needed to verify signatures on messages (like anon keys) coming from the Aggregator.

        Args:
            agg_pk (tuple): The Aggregator's signing public key structure.
        """
        self.agg_pk = agg_pk

    def get_sm_id_And_encryption_key(self):
        """Returns ID and Encryption Key."""
        message_to_verify = self.id + str(self.ek.x) + str(self.ek.y)
        return (self.id, self.get_encryption_key(), self.pro.sig.schnorr_sign(self.__sk, self.pp, message_to_verify))
    

    def set_anon_key(self, anon_key_w_sign):
        """ 
        Receives the randomness (blinding factor) used in Mix_id().
        
        This allows the Smart Meter to locally reconstruct its "Anonymous Identity" (pk')
        without revealing its value.
        pk' = pk + g*r'
        
        It also verifies the Aggregator's signature on this assignment to ensure authenticity.

        Args:
            anon_key (tuple): A tuple containing (r_prime, signature).
                              r_prime is the blinding factor (EC Point or Scalar).
        """
        enc_anon_key, signature = anon_key_w_sign
        
        x = self.pro.ahe.dec(self.__dk, enc_anon_key[0])
        y = self.pro.ahe.dec(self.__dk, enc_anon_key[1])
        
        from Crypto.PublicKey import _point
        anon_key = _point.EccPoint(x, y, self.pp[0]._name)
        
        # anon_key_verified = self.pro.sig.schnorr_verify(self.agg_pk[0], self.agg_pk[1], str(r_prime), signature)
        anon_key_verified = self.pro.sig.schnorr_verify(self.agg_pk[0], self.agg_pk[1], str(x) + str(y), signature)
        if not anon_key_verified:
            raise ValueError("Anonymous key signature verification failed.")
        
        # The final Point on the curve (pk'). This is what the rest of the network sees as the sm identity.
        # self.anon_id = r_prime * self.pp[1]
        self.anon_id = anon_key

    def get_sm_baseline(self, m):
        """
        Generates a signed and encrypted report for a demand response event.

        Args:
            m (int): The message payload.

        Returns: 
            tuple: (User_Public_Key, (Timestamp, Ciphertexts, Signature))
                   This structure matches the input expected by the Aggregator/DSO.
        """

        if m > 0:
            self.participating = True

        t = int(time.time())
        baseline_report = self.pro.report(self.id, self.__sk, self.dso_ek, m, t, self.get_public_key())
        return baseline_report
    
    def get_sm_consumption(self):
        """ 
        Simulates generating a standard consumption report.
        
        Placeholder:
            Currently generates a random consumption value between 9 and 10 for testing.

        Returns: 
            tuple: The signed and encrypted report object.
        """
        t = int(time.time())

        # consume = random.randint(9, 10)
        consume = 8
        consumption_report = self.pro.report(self.id, self.__sk, self.dso_ek, consume, t, self.get_public_key())
        return consumption_report
    
    def is_participating(self):
        """
        Returns whether this SM has participated (sent a non-zero reduction) in the current event.
        """
        return self.participating

    def check_if_in_event(self, input):
        """
        Checks if this Smart Meter was selected for the event.

        The input is a list of Anonymous Public Keys (pk'). 
        The Smart Meter calculates its own pk' (pk + anon_id) and checks if it exists in the list.

        Args:
            input (list): A list of EC Points representing the anonymous public keys of selected participants.

        Returns:
            None: Sets the internal state `self.in_event`.
        """
        sm_pk_prime = (self.anon_id + self.pk)

        for anon_pk in input:
            if sm_pk_prime == anon_pk:
                print("SM: " + self.id + " is a participant in the event")
                self.in_event = True
                return
            else:
                self.in_event = False
    
    def in_event(self):
        """
        Getter for the event participation status.
        """
        return self.in_event