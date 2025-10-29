from petlib.ec import EcGroup
from petlib.bn import Bn
import hashlib

def hash_to_bn(*points, order):
    """Hash EC points deterministically into a scalar mod q."""
    h = hashlib.sha256()
    for P in points:
        h.update(P.export())   # serialize EC point bytes
    return Bn.from_binary(h.digest()) % order

# demo use
def elgamal_encrypt(sec_params, ek, m_point):
    """Encrypt a message point m_point under public key ek."""
    _, g, order = sec_params
    C1 = order * g
    C2 = m_point + order * ek
    return (C1, C2), order

def prove_correct_decryption(sec_params, ek, C1, C2, M, dk):
    """
    Prove that M = C2 - dk * C1 (i.e., correct ElGamal decryption)
    without revealing dk.
    Returns a non-interactive proof (A1, A2, s).
    """
    _, g, order = sec_params

    
    r = order.random()       # random nonce

    A1 = r * g      # commitment of ciphertext 1
    A2 = r * C1     # commitment of ciphertext 2

    c = hash_to_bn(g, ek, C1, C2, M, A1, A2, order=order)
    s = (r + c * dk) % order

    return (A1, A2, s)

def verify_correct_decryption(sec_params, ek, C1, C2, M, proof):
    """Verify a Chaum–Pedersen style NIZK proof of correct decryption."""
    _, g, order = sec_params

    A1, A2, s = proof

    V = C2 - M         # compute x * C1

    # C2 = M + order * ek
    # C2 = M + order * x * g
    # C2 - M = order * x * g
    # C2 - M = x * order * g
    # C2 - M = x * C1

    c = hash_to_bn(g, ek, C1, C2, M, A1, A2, order=order)

    check1 = (s * g == A1 + c * ek)
    check2 = (s * C1 == A2 + c * V)

    return check1 and check2


def demo():
    """Demo run of encryption, decryption and proof verification."""
    G = EcGroup(713)  # 713 = NIST P-256
    g = G.generator()
    q = G.order()
    sec_param = (G, g, q)

    # Generate keypair
    x = q.random()
    ek = x * g

    # Encode message as an EC point (simple example)
    # In real systems, you'd use proper EC encoding or ECIES mapping.
    m_scalar = Bn(42)
    M = m_scalar * g  # "message point"

    # Encrypt
    (C1, C2), _ = elgamal_encrypt(sec_param, ek, M)

    # Decrypt
    # M_dec = C2 - x * C1
    M_dec = C2.pt_add(C1.pt_mul(x).pt_neg())
    assert M_dec == M

    # Prove correct decryption
    proof = prove_correct_decryption(sec_param, ek, C1, C2, M, x)

    # Verify proof
    ok = verify_correct_decryption(sec_param, ek, C1, C2, M, proof)
    print("Proof verified:", ok)


if __name__ == "__main__":
    demo()
