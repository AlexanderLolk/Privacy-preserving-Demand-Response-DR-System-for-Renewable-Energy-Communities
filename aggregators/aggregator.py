from utils.procedures import Procedures
from utils.signature import schnorr_verify, schnorr_sign
import utils.anonym as anonym

class Aggregator:
    """ 
    
    """
    def __init__(self, init_id="agg_id", pp=None):
        self.pro = Procedures()
        if pp is None:
           pp = self.pro.pub_param()

        ((self.id, (self.pk, self.pp, self.s_proof)), self.sk) = self.pro.skey_gen(init_id, pp)
        
        # TODO: do we need ek for the aggregator?
        ((self.ek, _, self.e_proof), self.dk) = self.pro.ekey_gen_single(pp)

        self.participants = []
        self.participants_baseline_report = []
        self.participants_consumption_report = []
        self.pk_to_pk_prime = {}
    
    def get_id(self):
        """ 
        return: 
            str:
        """
        return self.id

    def get_public_key(self):
        """ 
        return:
            tuple[EcPt, tuple[EcGroup, EcPt, Bn], tuple[Bn, Bn, EcPt]]
        """
        return (self.pk, self.pp, self.s_proof)
    
    def get_encryption_key(self):
        """ 
        Returns:
            tuple[EcPt, tuple[EcGroup, EcPt, Bn], tuple[EcPt, tuple[EcPt, EcPt], tuple[EcPt, EcPt], Bn]]: 
        """
        return (self.ek, self.pp, self.e_proof)
    
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
        self.dk_share = key_share

    # MIX: create mixed anonymous pk set
    # Report: this is signed by the aggregator, the idea is to prove this specific aggregator did the mixing
    # send (pk_prime, πmix) to board
    def create_mixed_anon_pk_set(self, ID_pk):
        """
        Args:
          ID_pk: list[tuple[EcPt, tuple[EcGroup, EcPt, Bn], tuple[Bn, Bn, EcPt]]]
        """
        self.mix_anon_list = self.pro.mix_id(ID_pk)   

    def publish_mixed_keys(self):
        """ 
        return: 
            tuple[list[EcPt], 
            tuple[tuple[EcPt, EcPt, EcPt, EcPt, list[EcPt]], 
                tuple[Bn, Bn, Bn, Bn, list[Bn], list[Bn]], 
                list[EcPt],
                list[EcPt],
                EcPt,
                list[EcPt]]]
        """
        # publish (pk_prime, πmix)
        # TODO: sign the list? or each element?
        return (self.mix_anon_list[0], self.mix_anon_list[2])
    
    def set_anon_key_mix(self, sm):
        """
        Args:
          sm:  tuple[str, tuple[EcGroup, EcPt, Bn]]

        Returns:
            tuple[Bn, tuple[Bn, Bn, EcPt]]
        """
        # sm can be either (id, pk) or just pk
        if isinstance(sm, tuple):
            sm_pk = sm[0]
        else:
            sm_pk = sm

        _, g, _ = self.pp

        # using additive logic (pk + r*G)
        for r_prime in self.mix_anon_list[1]:

            # calculate r_prime * g
            blinding_factor = int(r_prime) * g

            # then add r_prime to public key
            pk_prime_check = sm_pk + blinding_factor
            
            for pk_prime in self.mix_anon_list[0]:
                if pk_prime_check == pk_prime:
                    sign_r_prime = schnorr_sign(self.sk, self.pp, str(blinding_factor))

                    # TODO NOT SURE IF STORING IS THE RIGHT WAY
                    pk_str = str((sm_pk.x, sm_pk.y))
                    self.pk_to_pk_prime[pk_str] = blinding_factor
                    
                    
                    return (blinding_factor, sign_r_prime)
        
        print("Public key not found in r_prime")
        return None


    # report
    # report is decrypted and verified
    # Report: remember there is a certain time period where smartmeters can/should sign up for an event (scenario: if there is one participant only, and that participant immidietly starting the event, that participant would be able to be figured out who they are)
    def check_sm_report(self, sm_report, sm_id="NOT_SAID", consumption=False):
        (pk, (t, cts, signature)) = sm_report
        # sm_pk_pt, group, _ = pk
        sm_pk = pk[0]
        pp = pk[1]
        # print("cts is " + str(cts))
        if not schnorr_verify(sm_pk, pp, str((t, cts)), signature):
            print("Signature verification failed.")
            return

        g = pp[1]
        
        # partial_from_agg = self.pro.ahe.partial_decrypt(cts, self.dk_share)
        # partial_from_dr = dr_aggregator.get_partial_decryption_share(cts)
        
        # partial_combined = partial_from_agg + partial_from_dr

        # print(f"combined length is {len(partial_combined)} of the partial decryptions")
        # msg_val = self.pro.ahe.threshold_decrypt(
        #     partial_combined,
        #     cts,
        #     self.thresh_params
        # )

        # print(f" decrypted msg value: {msg_val}")

        deterministic_check = self.pro.ahe.enc(self.dso_ek[0], 0, r=1)


        pk_prime = None
        for r_prime in self.mix_anon_list[1]:
            blinding_factor = int(r_prime) * g
            pk_prime_check = sm_pk + blinding_factor
            
            for pk_prime_candidate in self.mix_anon_list[0]:
                if pk_prime_check == pk_prime_candidate:
                    pk_prime = pk_prime_check
        
        if not consumption and cts != deterministic_check:
            print(f"{sm_id} wants to join DR event \n")
            self.participants_baseline_report.append(sm_report)
            self.participants.append(pk_prime)
        elif consumption:
            self.participants_consumption_report.append(sm_report)
            
    def get_participants(self):
        """ 
        return:
            list[EcPt]
        """
        return self.participants
    
    def get_participants_baseline(self):
        return self.participants_baseline_report
    
    def get_participants_consumption(self):
        """ 
        return:
            list[EcPt]
        """
        return self.participants_consumption_report
    
    def get_agg_id_And_encryption_key(self):
        """ 
        return:
            tuple[str, tuple[EcPt, tuple[EcGroup, EcPt, Bn], tuple[EcPt, tuple[EcPt, EcPt], tuple[EcPt, EcPt], Bn]]]
        """
        return (self.id, self.get_encryption_key())
    
    # Not implemented (see utils/anonym.py)
    def make_anonym(self, consumption=False):
        """ 
        return:
            tuple[tuple[Bn, tuple[Bn, Bn, EcPt]], tuple[EcPt, tuple[EcPt, EcPt], int, str(placeholder)]]
        """

        # TODO PART OF UNSURE STORING OF R_PRIME
        r_prime_list = []
        for (pk, _, _), _ in self.participants_baseline_report:
            pk_str = str((pk.x, pk.y))
            r_prime = self.pk_to_pk_prime[pk_str]
            r_prime_list.append(r_prime)

        if not consumption:
            return anonym.Anonym(self.get_participants_baseline(), r_prime_list, self.sk)
        
        return anonym.Anonym(self.get_participants_consumption(), r_prime_list, self.sk)
    
    def partial_dec_reports(self, baseline_BB, consumption_PBB):
        baseline_pk_to_part = {}
        consumption_pk_to_part = {}
        # baseline_part = []
        # consumption_part = []
        # print(f"\n\n\n in agg, len of get_participants = {len(self.get_participants())}\n\n\n")
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
    
    def partial_dec_equal_cts(self, equal_cts):
        partial_cts = []
        for ct in equal_cts:
            # print(f"\nct in partial_dec_equal_cts in agg: {ct}")
            partial_ct = self.pro.ahe.partial_decrypt(ct, self.dk_share)
            partial_cts.append(partial_ct)
        return partial_cts