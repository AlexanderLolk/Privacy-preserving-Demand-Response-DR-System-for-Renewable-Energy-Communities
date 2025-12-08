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
        # as a default
        self.participating = False

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
        
        # self.r_prime = r_prime # Store the randomness

        # _, g, _ = self.pp

        # Using additive to reconstruct identity
        # The blinding_factor is (r' * g). It is the vector you add to your position to hide where you started.
        # pk_prime = r_prime * g

        # The final Point on the curve (pk'). This is what the rest of the network sees as the sm identity.
        self.anon_id = r_prime

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

        if m > 0:
            self.participating = True

        t = int(time.time())
        baseline_report = self.pro.report(self.id, self.sk, self.dso_ek, m, t, self.get_public_key())
        return baseline_report
    
    def get_sm_consumption(self):
        """ 
            Returns: tuple[list[tuple[]], tuple[]]
        """
        t = int(time.time())

        # Placeholder since we dont have real data
        # while target reduction is 10
        consume = random.randint(9, 10)
        consumption_report = self.pro.report(self.id, self.sk, self.dso_ek, consume, t, self.get_public_key())
        return consumption_report
    
    def is_participating(self):
        return self.participating

    def check_if_in_event(self, input):
        """

        Args:
          input: [EcPt]

        """
        sm_pk_prime = (self.anon_id + self.pk)
        print("")

        # print(f"\nin sm as {self.id}, \ncheck_if_in_event's input: {str(input)} \nwith the anon_pk as: x = {self.anon_id.x}, y = {self.anon_id.x}")
        for anon_pk in input:
            # print(f"\nin sm as {self.id}, \ncheck_if_in_event's input: x = {anon_pk.x},\n y = {anon_pk.y} \nwith the anon_pk as: x = {sm_pk_prime.x},\n y = {sm_pk_prime.y}")
            if sm_pk_prime == anon_pk:
                print("SM: " + self.id + " is a participant in the event")
                self.in_event = True
                return
            else:
                # print("SM: " + self.id + " didnt get a inv")
                self.in_event = False
    
    def in_event(self):
        return self.in_event