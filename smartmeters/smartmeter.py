# participating user
# non-participating user

import time
from utils.generators import pub_param, skey_gen, report
from utils.signature import schnorr_verify

class SmartMeter:
    
    def __init__(self, init_id="sm_id", pp=None):
        if pp is None:
           pp = pub_param()

        ((self.id, (self.pk, self.pp, self.s_proof)), self.sk) = skey_gen(init_id, pp)

    def get_public_key(self):
        return (self.pk, self.pp, self.s_proof)

    def set_dso_public_keys(self, dso_pk, dso_ek):
        self.dso_pk = dso_pk
        self.dso_ek = dso_ek

    def set_agg_public_keys(self, agg_pk):
        self.agg_pk = agg_pk

    # Mix()
    # Report: We sign each anonymized public key to know it came from the aggregator who mixed it
    def set_anon_key(self, anon_key):
        anon_pk, signature = anon_key
        
        if not schnorr_verify(self.agg_pk[0], self.agg_pk[1], str(anon_pk), signature):
            print("Anonymous key signature verification failed.")
        
        self.anon_pk = anon_pk
        self.anon_id = self.pk.pt_mul(anon_pk)

    # Report()
    # TODO: make sure m shouldnt be something else (m is set to be 10, it's placeholder right now)
    def generate_and_send_report(self, m):
        t = int(time.time())
        return report(self.id, self.sk, self.dso_ek, m, t=t, user_pk=(self.pk, self.pp, self.s_proof))

    def get_sm_comsumption(self):
        return None
    
    def check_if_in_event(self, input):
        for anon_pk in input:
            if self.anon_id == anon_pk:
                print("SM: " + self.id + " is in the event")
                self.in_event = True
            else:
                self.in_event = False