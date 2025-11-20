# the DSO publishes a signed list of registered aggregators on
# BB. The DSO can update the list of registered smart meters and aggregators dynamically

from utils.generators import pub_param, skey_gen, ekey_gen, mix_id
from utils.signature import schnorr_verify, schnorr_sign
from utils.ec_elgamal import dec, make_table
import utils.anonym as anonym

class Aggregator:
    """ """

    def __init__(self, init_id="agg_id", pp=None):
        
        if pp is None:
           pp = pub_param()

        ((self.id, (self.pk, self.pp, self.s_proof)), self.sk) = skey_gen(init_id, pp)
        # TODO: do we need ek for the aggregator?
        ((self.ek, _, self.e_proof), self.dk) = ekey_gen(pp)

        self.participants = []
        self.participants_report = []
    
    def get_id(self):
        """ """
        return self.id

    def get_public_key(self):
        """ """
        return (self.pk, self.pp, self.s_proof)
    
    def set_dso_public_keys(self, dso_pk, dso_ek):
        """

        :param dso_pk: 
        :param dso_ek: 

        """
        self.dso_pk = dso_pk
        self.dso_ek = dso_ek
        
    def set_dso_dk(self, cipher_signature):
        """

        :param cipher_signature: 

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

        :param ID_pk: 

        """
        # mix_anon_list = [pk_prime, r_prime, πmix_proof]
        self.mix_anon_list = mix_id(ID_pk)   

    def publish_mixed_keys(self):
        """ """
        # publish (pk_prime, πmix)
        # TODO: sign the list? or each element?
        return (self.mix_anon_list[0], self.mix_anon_list[2])
    
    def set_anon_key_mix(self, sm):
        """

        :param sm: 

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
            blinding_factor = g.pt_mul(r_prime)
            # then add r_prime to public key
            # Old: anon_pk = sm_pk.pt_mul(r_prime)
            pk_prime_check = sm_pk.pt_add(blinding_factor)
            
            for pk_prime in self.mix_anon_list[0]:
                if pk_prime_check == pk_prime:
                    sign_r_prime = schnorr_sign(self.sk, self.pp, str(r_prime))
                    return (r_prime, sign_r_prime)
        
        print("Public key not found in r_prime")
        return None

    # report
    # report is decrypted and verified
    # Report: remember there is a certain time period where smartmeters can/should sign up for an event (scenario: if there is one participant only, and that participant immidietly starting the event, that participant would be able to be figured out who they are)
    def check_sm_report(self, sm_report):
        """

        :param sm_report: 

        """
        # pk is a tuble with (pk, pp, s_proof)
        (pk, (t, cts, signature)) = sm_report

        table = make_table(pk[1])

        if not schnorr_verify(pk[0], pk[1], str((t, cts)), signature):
            print(False)
            
        bin_msgs = [dec(self.dso_dk, pk[1], table, ct) for ct in cts]

        # msg = dec(self.dso_dk, self.pp, table, ct="")
        msg = "".join([str(x) for x in bin_msgs])
        
        # (_, 2) means from bin to int
        msg = int(msg, 2)

        _, g, _ = self.pp

        pk_prime = None
        for r_prime in self.mix_anon_list[1]:
            # Using additive
            # Old multiplied, like so anon_pk = pk[0].pt_mul(r_prime)
            blinding_factor = g.pt_mul(r_prime)
            pk_prime_check = pk[0].pt_add(blinding_factor)
            
            for pk_prime in self.mix_anon_list[0]:
                if pk_prime_check == pk_prime:
                    pk_prime = pk_prime_check
        
        # participants are those with the msg (the msg is currently set to 10)
        if msg >= 0:
            print("SM wants to join DR event")
            self.participants_report.append(sm_report)
            self.participants.append(pk_prime)
            
    def get_participants(self):
        """ """
        return self.participants
    
    def get_agg_id_And_encryption_key(self):
        """ """
        return (self.id, self.ek)
    
    # Not implemented (see utils/anonym.py)
    def make_anonym(self):
        """ """
        return anonym.Anonym(self.participants_report, self.mix_anon_list[1], self.sk)