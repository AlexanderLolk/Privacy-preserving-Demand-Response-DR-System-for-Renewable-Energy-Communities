from petlib.ec import EcGroup
from petlib.bn import Bn
import hashlib

def hash_to_bn(*points, q):
    """Hash EC points deterministically into a scalar mod q."""
    h = hashlib.sha256()
    for P in points:
        h.update(P.export())   # serialize EC point bytes
    return Bn.from_binary(h.digest()) % q

def elgamal_encrypt(G, H, m_point):
    """Encrypt a message point m_point under public key H."""
    q = G.order()
    r = q.random()
    C1 = r * G.generator()
    C2 = m_point + r * H
    return (C1, C2), r

def prove_correct_decryption(G, H, C1, C2, M, x):
    """
    Prove that M = C2 - x*C1 (i.e., correct ElGamal decryption)
    without revealing x.
    Returns a non-interactive proof (A1, A2, s).
    """
    q = G.order()
    g = G.generator()

    V = C2 - M           # compute 'v' = c2 - m
    r = q.random()       # random nonce

    A1 = r * g
    A2 = r * C1

    e = hash_to_bn(g, H, C1, C2, M, A1, A2, q=q)
    s = (r + e * x) % q

    return (A1, A2, s)


def verify_correct_decryption(G, H, C1, C2, M, proof):
    """Verify a Chaum–Pedersen style NIZK proof of correct decryption."""
    A1, A2, s = proof
    q = G.order()
    g = G.generator()
    V = C2 - M

    e = hash_to_bn(g, H, C1, C2, M, A1, A2, q=q)

    check1 = (s * g == A1 + e * H)
    check2 = (s * C1 == A2 + e * V)

    return check1 and check2


def demo():
    """Demo run of encryption, decryption and proof verification."""
    G = EcGroup(713)  # 713 = NIST P-256
    g = G.generator()
    q = G.order()

    # Generate keypair
    x = q.random()
    H = x * g

    # Encode message as an EC point (simple example)
    # In real systems, you'd use proper EC encoding or ECIES mapping.
    m_scalar = Bn(42)
    M = m_scalar * g  # "message point"

    # Encrypt
    (C1, C2) = elgamal_encrypt(G, H, M)

    # Decrypt
    M_dec = C2 - x * C1
    assert M_dec == M

    # Prove correct decryption
    proof = prove_correct_decryption(G, H, C1, C2, M, x)

    # Verify proof
    ok = verify_correct_decryption(G, H, C1, C2, M, proof)
    print("Proof verified:", ok)


if __name__ == "__main__":
    demo()
