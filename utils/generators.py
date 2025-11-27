from petlib.ec import EcGroup, Bn
import random
import utils.signature as sig
import utils.NIZKP as nizkp
import utils.ec_elgamal as ahe
import utils.shuffle as shuffle
from utils.dec_proof import prove_correct_decryption
import threshold_crypto as tc

# def pub_param(nid=713):
#     """Create and return elliptic-curve public parameters.

#     Args:
#         nid (int): petlib curve identifier (default 713 == NIST P-256).

#     Returns:
#         tuple[EcGroup, EcPt, Bn]:
#     """
#     group_G = EcGroup(nid)
#     # g is the base point of the curve, which is also called the generator
#     g = group_G.generator()
#     order = group_G.order()
    
#     return (group_G, g, order)

def pub_param(curve="P-256"):
    curve_params = tc.CurveParameters(curve)
    return curve_params

pp = pub_param()

# SKey_Gen(id, pp) → ((id, pk), sk)
# SKeyGen(id, pp) to generate a signing key pair ((id, pk), sk) and publishes (id, pk) 
# generates signature key pair (sk, pk) for identity id
def skey_gen(id=random, pp=None):
    """Generate a signing keypair and a Schnorr NIZKP for the public key.

    Args:
        id: identifier for the key owner (may be a random generator by default).
        pp: public parameters tuple as returned by `pub_param`.

    Returns:
        tuple[str, tuple[EcPt, tuple[EcGroup, EcPt, Bn], tuple[Bn, Bn, EcPt]], Bn]: 
            ((id, (pk, pp, proof)), sk)
            where `pk` is the public signing key, `proof` is a Schnorr NIZKP,
            and `sk` is the signing secret key.
    """
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
    """Generate an ElGamal encryption keypair and a sample decryption proof.

    This function also computes a short non-interactive proof for a sample
    message to allow verifiers to check that the secret key can decrypt
    correctly.

    Args:
        pp (tuple[EcGroup, EcPt, Bn]): 

    Returns:
        tuple[tuple[EcPt, tuple[EcGroup, EcPt, Bn], tuple[EcPt, tuple[EcPt, EcPt], tuple[EcPt, EcPt], Bn]], Bn]: 
        where `ek` is the public encryption key,
        πdk` is the produced proof, and `dk` is the secret key.
    """
    if pp is None:  
        pp = pub_param()
    ek, dk = ahe.key_gen(pp)

    # TODO maybe change this to something random
    m_scalar = Bn(42)   # just a sample message for proof

    # (C1, C2) = elgamal_encrypt(pp, ek, M)
    cts = ahe.enc(ek, pp, m_scalar)

    # Generate proof of correct decryption
    πdk = prove_correct_decryption(ek, pp, m_scalar, dk)
    return ((ek, pp, πdk), dk)


# mix shuffles a n anonymized list of pk_i
# REPORT:
# id_a_pk[] is a list of public keys
# sends an anonymized list of public keys along with the proof of shuffle
def mix_id(ID_pk):
    """Anonymise and shuffle a list of identity public keys.

    Args:
        ID_pk (list[tuple[EcPt, tuple[EcGroup, EcPt, Bn], tuple[Bn, Bn, EcPt]]]): tuple of tuples (id, (pk, pp, proof)).

    Returns:
        tuple[list[EcPt], 
            tuple[tuple[EcPt, EcPt, EcPt, EcPt, list[EcPt]], 
                tuple[Bn, Bn, Bn, Bn, list[Bn], list[Bn]], 
                list[EcPt],
                list[EcPt],
                EcPt,
                list[EcPt]]]:
    """
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
    # TODO is pp[1] = pk?
    πmix_proof= shuffle.GenProof(Id_A_pk, e_prime, r_prime, ψ, pk=pp[1])

    return (e_prime, r_prime, πmix_proof)

# Report(id, sk, ek, m, t) → (pk, (t, ct, σ))
user_info = {}

def report(id, sk, ek, m, t, user_pk):
    """Create a report by encrypting a message and signing the tuple.

    The message `m` is converted to binary and each bit is encrypted with
    the provided ElGamal key. The resulting ciphertexts are then signed
    using the user's signing key.

    Args:
        id (str): reporter identifier.
        sk (Bn): reporter signing secret key.
        ek (EcPt): encryption keypair/parameters expected by `ahe.enc`.
        m (int): integer message to be encoded as binary bits.
        t (int): timestamp or round identifier included in the signed message.
        user_pk (EcPt): the reporter's public key tuple (pk, pp, proof)

    Returns:
        tuple[tuple[EcPt, tuple[EcGroup, EcPt, Bn], tuple[Bn, Bn, EcPt]], tuple[int, list[tuple[EcPt, EcPt]], tuple[Bn, Bn, EcPt]]]:
            (user_pk, (t, ct, signing_σ))
    """
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