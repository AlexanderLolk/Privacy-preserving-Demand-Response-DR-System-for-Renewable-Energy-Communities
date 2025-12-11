import time
import random
from utils.procedures import Procedures

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
        ((self.id, (self.pk, self.pp, self.s_proof)), self.sk) = self.pro.skey_gen(init_id, pp)
        
        # as a default
        self.participating = False

    def get_public_key(self):
        """
        Retrieves the Smart Meter's public key package.

        Returns:
            tuple: (Public_Key_Point, Public_Params, Proof_of_Knowledge)
        """
        return (self.pk, self.pp, self.s_proof)

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

    def set_anon_key(self, anon_key):
        """ 
        Receives the randomness (blinding factor) used in Mix_id().
        
        This allows the Smart Meter to locally reconstruct its "Anonymous Identity" (pk')
        without revealing its value.
        pk' = pk + r'
        
        It also verifies the Aggregator's signature on this assignment to ensure authenticity.

        Args:
            anon_key (tuple): A tuple containing (r_prime, signature).
                              r_prime is the blinding factor (EC Point or Scalar).
        """
        r_prime, signature = anon_key
        
        if not self.pro.sig.schnorr_verify(self.agg_pk[0], self.agg_pk[1], str(r_prime), signature):
            print("Anonymous key signature verification failed.")
        
        # The final Point on the curve (pk'). This is what the rest of the network sees as the sm identity.
        self.anon_id = r_prime

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
        baseline_report = self.pro.report(self.id, self.sk, self.dso_ek, m, t, self.get_public_key())
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

        consume = random.randint(9, 10)
        consumption_report = self.pro.report(self.id, self.sk, self.dso_ek, consume, t, self.get_public_key())
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
        # print("")

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