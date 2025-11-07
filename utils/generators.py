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
    
    return (group_G, g, order)

pp = pub_param()

# SKey_Gen(id, pp) → ((id, pk), sk)
# generates signature key pair (sk, pk) for identity id
def skey_gen(id=random, pp=None):
    if pp is None:
        pp = pub_param()
    sk, pk = sig.key_gen(pp)
    proof =  nizkp.schnorr_NIZKP_proof(pk, pp, sk)
    return ((id, (pk, pp, proof)), sk)

# EKeyGen(pp) → (ek, dk): On input of the public parameter pp, executes (ek, dk) ← AHE.KeyGen(1λ)
# which outputs encryption key pair.
# It then computes πdk ← Proofdk((pp, ek), dk), updates ek such
# that ek contains pp along with πdk, and returns (ek, dk).
def ekey_gen(pp=None):
    if pp is None:  
        pp = pub_param()
    ek, dk = ahe.key_gen(pp)

    m_scalar = Bn(42)   # just a sample message for proof
    M = m_scalar * pp[1]

    (C1, C2) = elgamal_encrypt(pp, ek, M)

    # Generate proof of correct decryption
    πdk = prove_correct_decryption(pp, ek, C1, C2, M, dk)
    return ((ek, pp, πdk), dk)


# mix shuffles a n anonymized list of pk_i
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

    return (pk, (t, ct, signing_σ))