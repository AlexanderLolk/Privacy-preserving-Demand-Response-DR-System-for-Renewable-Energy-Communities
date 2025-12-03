# the DSO publishes a signed list of registered aggregators on
# BB. The DSO can update the list of registered smart meters and aggregators dynamically

from utils.generators import pub_param, skey_gen, ekey_gen_single, mix_id
from utils.signature import schnorr_verify, schnorr_sign
# from utils.ec_elgamal import dec #, make_table
import utils.anonym as anonym

class Aggregator:
    """ """

    def __init__(self, init_id="agg_id", pp=None):
        
        if pp is None:
           pp = pub_param()

        ((self.id, (self.pk, self.pp, self.s_proof)), self.sk) = skey_gen(init_id, pp)
        # TODO: do we need ek for the aggregator?
        ((self.ek, _, self.e_proof), self.dk) = ekey_gen_single(pp)

        self.participants = []
        self.participants_report = []
    
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
        
    def set_dso_dk(self, cipher_signature):
        """

        Args:
          cipher_signature: Bn

        """
        # print("(Not implemented) In agg.set_dso_dk: got un-encrypted dso dk")
        self.dso_dk = cipher_signature

        # # cipher_signature is expected to be (ciphertext, signature)
        # ciphertext, signature = cipher_signature

        # # Build table for small messages (make_table maps EcPt -> int for a range)
        # table = make_table(self.pp)

        # # Decrypt: dec returns an EcPt (or previously returned table lookup)
        # plain_pt = dec(self.dk, self.pp, table, ciphertext)

        # # Try to convert the EcPt to an integer via the table, otherwise keep the EcPt
        # if plain_pt in table:
        #     dk_val = table[plain_pt]
        # else:
        #     dk_val = plain_pt

        # # Verify the DSO signature on the string form of the key
        # try:
        #     valid = schnorr_verify(self.dso_pk, self.pp, str(dk_val), signature)
        # except Exception:
        #     valid = False

        # if valid:
        #     self.dso_dk = dk_val
        #     print("DSO decryption key received and verified.")
        # else:
        #     self.dso_dk = None
        #     print("Failed to verify DSO signature.")

    # MIX: create mixed anonymous pk set
    # Report: this is signed by the aggregator, the idea is to prove this specific aggregator did the mixing
    # send (pk_prime, πmix) to board
    def create_mixed_anon_pk_set(self, ID_pk):
        """

        Args:
          ID_pk: list[tuple[EcPt, tuple[EcGroup, EcPt, Bn], tuple[Bn, Bn, EcPt]]]
        """
        # mix_anon_list = [pk_prime, r_prime, πmix_proof]
        self.mix_anon_list = mix_id(ID_pk)   

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

            # calculate r_prime * G
            # blinding_factor = g.pt_mul(r_prime)
            blinding_factor = int(r_prime) * g
            # then add r_prime to public key
            # Old: anon_pk = sm_pk.pt_mul(r_prime)
            pk_prime_check = sm_pk + blinding_factor
            
            for pk_prime in self.mix_anon_list[0]:
                if pk_prime_check == pk_prime:
                    sign_r_prime = schnorr_sign(self.sk, self.pp, str(r_prime))
                    return (r_prime, sign_r_prime)
        
        print("Public key not found in r_prime")
        return None

    # report
    # report is decrypted and verified
    # Report: remember there is a certain time period where smartmeters can/should sign up for an event (scenario: if there is one participant only, and that participant immidietly starting the event, that participant would be able to be figured out who they are)
    # TODO handle threshold partial decryption for this
    def check_sm_report(self, sm_report, dr_aggregator):
        
        (pk, (t, cts, signature)) = sm_report
        # sm_pk_pt, group, _ = pk
        sm_pk_pt = pk[0]
        pp = pk[1]

        if not schnorr_verify(sm_pk_pt, pp, str((t, cts)), signature):
            print("Signature verification failed.")
            return

        # gen_point = group.generator()
        # identity_point = group.infinite() 
        g = pp.P
        identity_point = 0 * g

        decrypted_bits = []

        # 3. Iterate through ciphertexts (bits)
        # for (c1, c2) in cts:
        #     share_agg = c1.pt_mul(self.sk_share)

        #     share_dr = dr_aggregator.get_partial_decryption_share(c1)

        #     share_total = share_agg.pt_add(share_dr)

        #     msg_point = c2.pt_sub(share_total)

        #     if msg_point == identity_point:
        #         decrypted_bits.append("0")
        #     elif msg_point == gen_point:
        #         decrypted_bits.append("1")
        #     else:
        #         print("Decryption Error: Point matches neither 0 nor 1.")
        #         return
        for (c1, c2) in cts:
            share_agg = int(self.dk_share) * c1

            share_dr = dr_aggregator.get_partial_decryption_share(c1)

            share_total = share_agg + share_dr

            msg_point = c2 + (-share_total)

            if msg_point == identity_point:
                decrypted_bits.append("0")
            elif msg_point == g:
                decrypted_bits.append("1")
            else:
                print("Decryption Error: Point matches neither 0 nor 1.")
                return

        msg_str = "".join(decrypted_bits)
        msg_val = int(msg_str, 2)

        pk_prime = None
        for r_prime in self.mix_anon_list[1]:
            # blinding_factor = g.pt_mul(r_prime)
            # pk_prime_check = pk[0].pt_add(blinding_factor)
            blinding_factor = int(r_prime) * g
            pk_prime_check = pk[0] + blinding_factor
            
            for pk_prime in self.mix_anon_list[0]:
                if pk_prime_check == pk_prime:
                    pk_prime = pk_prime_check
        
        if msg_val >= 0:
            print("SM wants to join DR event")
            self.participants_report.append(sm_report)
            self.participants.append(pk_prime)

    # def check_sm_report(self, sm_report):
    #     """

    #     Args:
    #       sm_report: tuple[tuple[EcPt, tuple[EcGroup, EcPt, Bn], tuple[Bn, Bn, EcPt]], tuple[int, list[tuple[EcPt, EcPt]], tuple[Bn, Bn, EcPt]]]

    #     """
    #     # pk is a tuble with (pk, pp, s_proof)
    #     (pk, (t, cts, signature)) = sm_report

    #     table = make_table(pk[1])

    #     if not schnorr_verify(pk[0], pk[1], str((t, cts)), signature):
    #         print(False)
            
    #     bin_msgs = [dec(self.dso_dk, pk[1], table, ct) for ct in cts]

    #     # msg = dec(self.dso_dk, self.pp, table, ct="")
    #     msg = "".join([str(x) for x in bin_msgs])
        
    #     # (_, 2) means from bin to int
    #     msg = int(msg, 2)

    #     _, g, _ = self.pp

    #     pk_prime = None
    #     for r_prime in self.mix_anon_list[1]:
    #         # Using additive
    #         # Old multiplied, like so anon_pk = pk[0].pt_mul(r_prime)
    #         blinding_factor = g.pt_mul(r_prime)
    #         pk_prime_check = pk[0].pt_add(blinding_factor)
            
    #         for pk_prime in self.mix_anon_list[0]:
    #             if pk_prime_check == pk_prime:
    #                 pk_prime = pk_prime_check
        
    #     # participants are those with the msg (the msg is currently set to 10)
    #     if msg >= 0:
    #         print("SM wants to join DR event")
    #         self.participants_report.append(sm_report)
    #         self.participants.append(pk_prime)
            
    def get_participants(self):
        """ 
        return:
            list[EcPt]
        """
        return self.participants
    
    def get_agg_id_And_encryption_key(self):
        """ 
        return:
            tuple[str, tuple[EcPt, tuple[EcGroup, EcPt, Bn], tuple[EcPt, tuple[EcPt, EcPt], tuple[EcPt, EcPt], Bn]]]
        """
        return (self.id, self.get_encryption_key())
    
    # Not implemented (see utils/anonym.py)
    def make_anonym(self):
        """ 
        return:
            tuple[tuple[Bn, tuple[Bn, Bn, EcPt]], tuple[EcPt, tuple[EcPt, EcPt], int, str(placeholder)]]
        """

        # list[tuple[tuple[EcPt, tuple[EcGroup, EcPt, Bn], tuple[Bn, Bn, EcPt]], tuple[int, list[tuple[EcPt, EcPt]], tuple[Bn, Bn, EcPt]]]],
        # list[EcPt],
        # Bn

        return anonym.Anonym(self.participants_report, self.mix_anon_list[1], self.sk)