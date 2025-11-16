from utils.generators import ekey_gen, pub_param, skey_gen


class DR_Aggregator:

    def __init__(self, init_id="dr_agg_id", pp=None):
        if pp is None:
            pp = pub_param()

        ((self.id, (self.pk, self.pp, self.s_proof)), self.sk) = skey_gen(init_id, pp)
        
        # TODO: do we need ek for the dr aggregator?
        ((self.ek, _, self.e_proof), self.dk) = ekey_gen(pp)

    def set_anonym_reports(self):
        return None
    
    def set_psudo_anonymous_iden(self):
        return None
    
    def select_random_sms(self):
        return None
