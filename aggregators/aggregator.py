# the DSO publishes a signed list of registered aggregators on
# BB. The DSO can update the list of registered smart meters and aggregators dynamically

from utils.generators import pub_param, skey_gen, ekey_gen, mix_id
from utils.signature import schnorr_verify, schnorr_sign
from utils.ec_elgamal import dec, make_table
import utils.anonym as anonym

# TODO: REMEMBER TO ASK
# So since the sm list given to BB is not encrypted, 
# and the r' sent to sm is also not encrypted, 
# what is stopping someone from take the r' when sent, so they can find out how is part of the event 

class Aggregator:

    def __init__(self, init_id="agg_id", pp=None):
        
        if pp is None:
           pp = pub_param()

        ((self.id, (self.pk, self.pp, self.s_proof)), self.sk) = skey_gen(init_id, pp)
        # TODO: do we need ek for the aggregator?
        ((self.ek, _, self.e_proof), self.dk) = ekey_gen(pp)
    
    def get_id(self):
        return self.id

    def get_public_key(self):
        return (self.pk, self.pp, self.s_proof)
    
    def set_dso_public_keys(self, dso_pk, dso_ek):
        self.dso_pk = dso_pk
        self.dso_ek = dso_ek
        
    def set_dso_dk(self, ciphertext, signature):
        # TODO make sure signature is valid and encrypted data is from DSO
        
        table = make_table(self.pp)
        msg = dec(self.dk, self.pp, table, ciphertext)
        
        if schnorr_verify(self.dso_pk, self.pp, msg, signature):
            print(True)
        else:
            print(False)

        # TODO should be a ec_point (is string now) check petlib if it has something to convert it with
        self.dso_dk = msg

    # MIX: create mixed anonymous pk set
    # TODO: this should be signed by the aggregator, the idea is to prove this specific aggregator did the mixing
    # send (pk_prime, πmix) to board
    def create_mixed_anon_pk_set(self, ID_pk):
        # mix_anon_list = [pk_prime, r_prime, πmix_proof]
        self.mix_anon_list = mix_id(ID_pk)   

    def publish_mixed_keys(self):
        # publish (pk_prime, πmix)
        # TODO: sign the list? or each element?
        return (self.mix_anon_list[0], self.mix_anon_list[2])
    
    # def set_anon_key_mix(self, sm):
    #     # sm = (id, pk)
        
    #     # TODO make the for loops more efficient
    #     for r_prime in self.mix_anon_list[1]:
    #         # sm_pk = (sm[1] * r_prime)
    #         sm_pk = (sm.pt_mul(r_prime))
             
    #         for pk_prime in self.mix_anon_list[0]:
    #             if sm_pk == pk_prime:
    #                 sign_r_prime = schnorr_sign(self.sk, self.pp, r_prime)
    #                 return (r_prime, sign_r_prime)
        
    #     print("Public key not found in r_prime")
    #     return None
    
    def set_anon_key_mix(self, sm):
        # sm can be either (id, pk) or just pk
        if isinstance(sm, tuple):
            sm_pk = sm[1]
        else:
            sm_pk = sm

        for r_prime in self.mix_anon_list[1]:
            anon_pk = sm_pk.pt_mul(r_prime)
            for pk_prime in self.mix_anon_list[0]:
                if anon_pk == pk_prime:
                    sign_r_prime = schnorr_sign(self.sk, self.pp, str(r_prime))
                    return (r_prime, sign_r_prime)
        print("Public key not found in r_prime")
        return None

    # report
    # report is decrypted and verified
    # TODO  maybe it should also sign it after having verified it before sending to the board?
    def set_sm_report(self, sm_report):
        # pk is a tuble with (pk, pp, s_proof)
        (pk, (t, ct, signature)) = sm_report
        
        table = make_table(self.pp)
        msg = dec(self.dso_dk, self.pp, table, ct)
        
        if schnorr_verify(self.dso_pk, self.pp, msg, signature):
            print(True)
        else:
            print(False)
            
        # TODO error handling
        if msg >= 0:
            print("SM wants to join DR event")
            self.participants.append(sm_report)
            
    def get_participants(self):
        return self.participants
    
    # Not implemented (see utils/anonym.py)
    def make_anonym(self):
        anonym.Anonym(inputs="", r_prime_list=[""], secret_key_T="")
        return "not implemented"
        
        



# import smartmeters.smartmeter as smartmeter
# import dso.DSO as dso
# import utils.ec_elgamal as ahe
# import utils.dec_proof as dec_proof
# import os

# NUM_AGG = 4

# agg_keys = []
# agg_info = {}
# agg_names = []
# agg_iden = []
# dso_ek = None
# dso_dk = None

# def make_aggregator(pp):
#     base_dir = os.path.dirname(os.path.abspath(__file__))
#     names_path = os.path.join(base_dir, "../aggregators/names.txt")

#     # user names and ids
#     with open(names_path, "r") as file:
#         for line in file:
#             words = line.strip().split()
#             ids = [word[0] for word in words if word]
#             ids = ids[0] + ". " + ids[1] 
#             agg_names.append(line.strip())
#             agg_iden.append(ids)

#     # aggregator's public keys
#     for i in range(NUM_AGG):
#         agg_id = agg_iden[i]
#         ((id, (pk, pp, proof)), sk) = skey_gen(pp)
#         verification = (pk, pp, proof)
#         agg_info[agg_id] = verification
#     return agg_info

# def get_agg_signature(pp):
#     return make_aggregator(pp)

# r_prime = []
# # MIX: create mixed anonymous pk set
# # send (pk', πmix) to board
# def create_mixed_anon_pk_set(ID_pk):
#     global r_prime
#     e_prime, r_prime, πmix_proof = mix_id(ID_pk)
#     return (e_prime, r_prime, πmix_proof)

# # send r' to users
# def publish_anon_key():
#     return r_prime

# def get_report_from_users():
#     user_reports = smartmeter.generate_and_send_report()
#     return user_reports

# # This is done so the dk can be used in the Eval function 
# def get_encryption_key_set():
#     global dso_ek
#     global dso_dk

#     dso_ek, dso_dk = dso.get_key_set()
