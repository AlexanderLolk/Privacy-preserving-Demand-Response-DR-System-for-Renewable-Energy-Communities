import time
import random
from utils.signature import schnorr_verify
from utils.procedures import Procedures


class SmartMeter:
    """ """
    
    def __init__(self, init_id="sm_id", pp=None):
        self.pro = Procedures()
        
        if pp is None:
           pp = self.pro.pub_param()

        ((self.id, (self.pk, self.pp, self.s_proof)), self.sk) = self.pro.skey_gen(init_id, pp)

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

    def set_agg_public_keys(self, agg_pk):
        """

        Args:
          agg_pk: tuple[EcPt, tuple[EcGroup, EcPt, Bn], tuple[Bn, Bn, EcPt]]

        Returns:

        """
        self.agg_pk = agg_pk

    # Mix()
    def set_anon_key(self, anon_key):
        """ Receives the randomness used to mix this sm's key.
        Reconstructs the anonymous identity (pk') using pk + (r' * g).
        
        Args:
            anon_key: tuple[EcPt, tuple[EcPt, Bn]]: 

        """

        # r_prime is the randomness used in the mixing
        r_prime, signature = anon_key
        
        if not schnorr_verify(self.agg_pk[0], self.agg_pk[1], str(r_prime), signature):
            print("Anonymous key signature verification failed.")
        
        self.r_prime = r_prime # Store the randomness

        _, g, _ = self.pp

        # Using additive to reconstruct identity
        # The blinding_factor is (r' * g). It is the vector you add to your position to hide where you started.
        pk_prime = r_prime * g

        # The final Point on the curve (pk'). This is what the rest of the network sees as the sm identity.
        self.anon_id = self.pk + pk_prime

    # Report()
    # TODO: make sure m shouldnt be something else (main.py: m is set to be 10, it's placeholder right now)
    def generate_and_send_report(self, m):
        """

        Args:
          m: TODO

        Returns: 
            tuple[tuple[EcPt, tuple[EcGroup, EcPt, Bn], tuple[Bn, Bn, EcPt]], tuple[int, list[tuple[EcPt, EcPt]], tuple[Bn, Bn, EcPt]]]
            (user_pk, (t, ct, signing_σ))

        """
        t = int(time.time())
        return self.pro.report(self.id, self.sk, self.dso_ek, m, t=t, user_pk=(self.pk, self.pp, self.s_proof))
    
    def get_sm_comsumption(self):
        """ 
            Returns: tuple[list[tuple[]], tuple[]]
        """
        # Placeholder since we dont have real data
        # while target reduction is 10
        t = int(time.time())
        consume = random.randint(9, 10)
        ct_consum, signed_consum = self.pro.consumption_report(self.dso_ek, self.sk, consume, t)

        return ct_consum, signed_consum
    
    def check_if_in_event(self, input):
        """

        Args:
          input: [EcPt]

        """
        for anon_pk in input:
            if self.anon_id == anon_pk:
                print("SM: " + self.id + " is in the event")
                self.in_event = True
            else:
                self.in_event = False