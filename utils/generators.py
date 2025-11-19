from petlib.ec import EcGroup, Bn
import random
import utils.signature as sig
import utils.NIZKP as nizkp
import utils.ec_elgamal as ahe
import utils.shuffle as shuffle
from utils.dec_proof import prove_correct_decryption

def pub_param(nid=713):
    """ """
    group_G = EcGroup(nid)
    # g is the base point of the curve, which is also called the generator
    g = group_G.generator()
    order = group_G.order()
    
    return (group_G, g, order)

pp = pub_param()

# SKey_Gen(id, pp) → ((id, pk), sk)
# SKeyGen(id, pp) to generate a signing key pair ((id, pk), sk) and publishes (id, pk) 
# generates signature key pair (sk, pk) for identity id
def skey_gen(id=random, pp=None):
    """ """
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
    """ """
    if pp is None:  
        pp = pub_param()
    ek, dk = ahe.key_gen(pp)

    # TODO maybe change this to something random
    m_scalar = Bn(42)   # just a sample message for proof

    # (C1, C2) = elgamal_encrypt(pp, ek, M)
    (C1, C2) = ahe.enc(ek, pp, m_scalar)

    # Generate proof of correct decryption
    πdk = prove_correct_decryption(ek, pp, m_scalar, dk)
    return ((ek, pp, πdk), dk)


# mix shuffles a n anonymized list of pk_i
# REPORT:
# id_a_pk[] is a list of public keys
# sends an anonymized list of public keys along with the proof of shuffle
def mix_id(ID_pk):
    """ """
    # ID_pk: list of tuples (id, (pk, pp, proof))
    
    if not ID_pk:
        return ([], {}, None)
    
    N = len(ID_pk)
    Id_A_pk = []
    for idpk in ID_pk:
        pk = idpk[1][0]
        Id_A_pk.append(pk)

    e_prime, r_prime, ψ = shuffle.GenShuffle(Id_A_pk) 
    # proof of shuffle and anonymised list of pks
    πmix_proof= shuffle.GenProof(Id_A_pk, e_prime, r_prime, ψ, pk=pp[1])

    return (e_prime, r_prime, πmix_proof)

# Report(id, sk, ek, m, t) → (pk, (t, ct, σ))
user_info = {}

def report(id, sk, ek, m, t, user_pk):
    """ """
    # to get pk sended back
    pk = user_pk[0]
    pp = user_pk[1]

    # print("bin m: " + bin(10))

    # convert message to binary in a list of bits
    mbin = [int(x) for x in bin(m)[2:]]
    
    # encrypt
    ct = [ahe.enc(ek[0], ek[1], m) for m in mbin]

    # sign (pk = (pk, pp, proof))
    msg = str((t, ct))
    signing_σ = sig.schnorr_sign(sk, pp, msg)

    return (user_pk, (t, ct, signing_σ))