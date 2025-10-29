from petlib.ec import EcGroup, Bn
import random
import utils.signature as sig
import utils.NIZKP as nizkp
import utils.ec_elgamal as ahe
import utils.shuffle as shuffle
from utils.dec_proof import elgamal_encrypt, prove_correct_decryption

def pub_param(nid=713):
    group_G = EcGroup(nid)
    # g is the base point of the curve, which is also called the generator
    g = group_G.generator()
    
    order = group_G.order()
    # group_h = EcGroup(nid)
    
    # print(str(group_G))
    # print(str(g))
    # print(str(order.random()))
    # print(str(order.random()))
    # print(str(order.random()))

    return (group_G, g, order)

pp = pub_param()

# SKey_Gen(id, pp) → ((id, pk), sk)
# generates signature key pair (sk, pk) for identity id
def skey_gen(id=random, pp=None):
    if pp is None:
        pp = pub_param()
    sk, pk = sig.key_gen(pp)
    proof =  nizkp.schnorr_NIZKP_proof(pp, pk, sk)
    return ((id, (pk, pp, proof)), sk)

# EKeyGen(pp) → (ek, dk): On input of the public parameter pp, executes (ek, dk) ← AHE.KeyGen(1λ)
# which outputs encryption key pair.
# It then computes πdk ← Proofdk((pp, ek), dk), updates ek such
# that ek contains pp along with πdk, and returns (ek, dk).
# TODO change proof to correct decryption (so 'm' is also decrypted correct)
# def ekey_gen(pp=None):
#     if pp is None:  
#         pp = pub_param()
#     ek, dk = ahe.key_gen(pp)
#     πdk = nizkp.schnorr_NIZKP_proof(pp, ek, dk)
#     return ((ek, pp, πdk), dk)

def ekey_gen(pp=None):
    if pp is None:  
        pp = pub_param()
    ek, dk = ahe.key_gen(pp)

    m_scalar = Bn(42)   # just a sample message for proof
    M = m_scalar * pp[1]

    (C1, C2), _ = elgamal_encrypt(pp, ek, M)

    # Generate proof of correct decryption
    πdk = prove_correct_decryption(pp, ek, C1, C2, M, dk)
    return ((ek, pp, πdk), dk)


# MixID(pk) → (pk′, r′, πmix): On input set IDpk = {(id, pk)}id∈ID computes shuffle and ran-
# domization to generate the mixed public key set pk′ = {pk′1, pk′2, ... , pk′n} where n = |ID|. It
# also computes πmix $ ← Proofmix((pk, pk′), ωmix), where πmix denotes the proof of knowledge of
# the correct mixing. The ωmix denotes the knowledge of secret shuffle and randomization.(here
# needs signature and different randomness r for each pki the user gets gr′
# not r′)

# TODO to be reworked
# mix should not encrypt but randomize the pk with r
def mix_id(ID_pk):
    # ID_pk: list of tuples (id, (pk, pp, proof))
    
    if not ID_pk:
        return ([], {}, None)
    
    N = len(ID_pk)
    Id_A_pk = []
    for idpk in ID_pk:
        # id = idpk[0] 
        pk = idpk[1][0]
        # Id_A_pk.append((id, pk))
        Id_A_pk.append(pk)

    e_prime, r_prime, ψ = shuffle.GenShuffle(Id_A_pk)
    # proof of shuffle and anonymised list of pks
    πmix_proof= shuffle.GenProof(Id_A_pk, e_prime, r_prime, ψ, pk="need to remove")

    return (e_prime, r_prime, πmix_proof)


    # # shuffle
    # pk_shuffled = pk_list.copy()
    # random.shuffle(pk_shuffled) # TODO use a secret shuffle
    
    # # lists and map
    # pk_mixed = []
    # r_map = {}
    # proofs = []

    # for id_val, (pk, pp, proof) in pk_shuffled:
    #     _, g, order = pp
    #     ωmix = order.random()
    #     pk_mark = pk + ωmix * g # randomize the key
    #     # compute difference and proof (pk_mark - pk = (pk + ωmix * g) - pk = ωmix * g)
    #     diff = pk_mark - pk
    #     πmix = nizkp.schnorr_NIZKP_proof(pp, diff, ωmix) # proof that can prove knowledge of ωmix
    #     pk_mixed.append((id_val, (pk_mark, pp, proof)))
    #     r_map[id_val] = ωmix
    #     proofs.append(πmix)

    # # πmix could be a hash/signature of all proofs, or a Merkle root, etc.
    # proof_bytes = b''.join([str(p).encode() for p in proofs])
    # πmix_ = hashlib.sha256(proof_bytes).hexdigest()

    # return (pk_mixed, r_map, proofs, πmix_)

# Report(id, sk, ek, m, t) → (pk, (t, ct, σ))

user_info = {}

def report(id, sk, ek, m, t, user_info):
    # to get pk sended back
    pk = user_info[id]
    pp = pk[1]

    # convert message to binary in a list of bits
    mbin = [int(x) for x in bin(m)[2:]]
    
    # encrypt
    ct = [ahe.enc(ek[1], ek[0], m) for m in mbin]

    # sign (pk = (pk, pp, proof))
    signing_σ = sig.schnorr_sign(pp, sk, str((t, ct)))

    # get pk
    return (pk, (t, ct, signing_σ))