from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
from utils.ec_elgamal import enc, dec, make_table
import hashlib

def hash_to_bn(*points, order):
    """Hash EC points deterministically into a scalar mod q.

    :param *points: 
    :param order: 

    """
    h = hashlib.sha256()
    for P in points:
        h.update(P.export())   # serialize EC point bytes
    return Bn.from_binary(h.digest()) % order

def prove_correct_decryption(ek, sec_params, M, dk):
    """Prove that M = C2 - dk * C1 (i.e., correct ElGamal decryption)
    without revealing dk.
    Returns a non-interactive proof (A1, A2, s).

    :param ek: 
    :param sec_params: 
    :param M: 
    :param dk: 

    """
    _, g, order = sec_params
    CT = enc(ek, sec_params, M)
    ct_0, ct_1 = CT

    if isinstance(M, EcPt):
        M_point = M
    elif isinstance(M, Bn):
        M_point = g.pt_mul(M)
    else:
        M_point = g.pt_mul(Bn(M))

    r = order.random()       # random nonce

    # A1 = r * g      # commitment of ciphertext 1
    # A2 = r * C1     # commitment of ciphertext 2
    commitment_ct_0 = g.pt_mul(r)    # commitment of ciphertext 1
    commitment_ct_1 = ct_0.pt_mul(r)     # commitment of ciphertext 2
    commitment_CT = (commitment_ct_0, commitment_ct_1)
    
    challenge = hash_to_bn(g, ek, ct_0, ct_1, M_point, commitment_ct_0, commitment_ct_1, order=order)
    # s = r + c * dk % order
    response = (r + challenge * dk) % order

    return (M_point, CT, commitment_CT, response)

def verify_correct_decryption(ek, sec_params, proof):
    """Verify a Chaum–Pedersen style NIZK proof of correct decryption.

    :param ek: 
    :param sec_params: 
    :param proof: 

    """
    _, g, order = sec_params
    M, CT, commitment_CT, s = proof
    ct_0, ct_1 = CT
    commitment_ct_0, commitment_ct_1 = commitment_CT
    
    if isinstance(M, EcPt):
        M_point = M
    elif isinstance(M, Bn):
        M_point = g.pt_mul(M)
    else:
        M_point = g.pt_mul(Bn(M))

    # V = C2 - M         
    # V = C2.pt_add(M.pt_neg()) 
    V = ct_1.pt_add(M_point.pt_neg()) 
    # V = C2.pt_add(Bn(M).int_neg())
    # V = C2 + (Bn(M).int_mul(Bn(-1)))
    
    # C2 = M + order * ek
    # C2 = M + order * x * g
    # C2 - M = order * x * g
    # C2 - M = x * order * g
    # C2 - M = x * C1

    c = hash_to_bn(g, ek, ct_0, ct_1, M_point, commitment_ct_0, commitment_ct_1, order=order)

    #  check1 = (s * g == A1 + c * ek)
    check1 = (g.pt_mul(s) == commitment_ct_0.pt_add(ek.pt_mul(c)))

    # check2 = (s * C1 == A2 + c * V)
    # check2 = (C1.pt_mul(s) == A2.pt_add(V.pt_mul(c)))
    check2 = (ct_0.pt_mul(s) == commitment_ct_1.pt_add(c * V))

    return check1 and check2


def demo():
    """Demo run of encryption, decryption and proof verification."""
    G = EcGroup(713)  # 713 = NIST P-256
    g = G.generator()
    q = G.order()
    sec_param = (G, g, q)

    # Generate keypair
    x = q.random()
    # ek = x * g 
    ek = g.pt_mul(x)

    # Encode message as an EC point (i.e. g * m_scalar, done as instance of in the proof)
    m_scalar = Bn(42)

    # Encrypt
    (C1, C2) = enc(ek, sec_param, m_scalar)

    # Decrypt
    # M_dec = C2 - x * C1
    # M_dec = C2.pt_add(C1.pt_mul(x).pt_neg())
    # assert M_dec == M

    tab = make_table(sec_param)
    print(dec(x, sec_param, tab, (C1, C2)))

    # Prove correct decryption
    proof = prove_correct_decryption(ek, sec_param, m_scalar, x)

    # Verify proof
    ok = verify_correct_decryption(ek, sec_param, proof)
    print("Proof verified:", ok)


if __name__ == "__main__":
    demo()