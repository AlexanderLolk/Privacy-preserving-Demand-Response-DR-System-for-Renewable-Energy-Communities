import hashlib
import threshold_crypto as tc

def hash_to_int(*points, order):
    """
    Hash EC points deterministically into a scalar mod q.
    
    Args:
        *points: Variable number of arguments (EC Points, integers, etc.).
        order: The curve order (q).

    Returns:
        int: A scalar value in [0, order-1].
    """
    h = hashlib.sha256()
    for P in points:
        if hasattr(P, "x") and hasattr(P, "y"):
            h.update(int(P.x).to_bytes(32, "big"))
            h.update(int(P.y).to_bytes(32, "big"))
        else:
            h.update(str(P).encode())
    return int.from_bytes(h.digest(), "big") % int(order)

def prove_correct_decryption(ek, pp, m, dk, ciphertext):
    """
    Prove that M = C2 - dk * C1 (i.e., correct ElGamal decryption)
    without revealing dk. Returns a non-interactive ZKP (A1, A2, s).

    Args:
        ek (ECC Point): ElGamal public key point (ek = dk * g).
        pp (tuple): Public parameters (Curve, G, Order).
        M (int): Message as an integer.
        dk (int): Secret key scalar.
        ciphertext (tuple): (C1, C2) ElGamal ciphertext pair.

    Returns:
        tuple: (m, ciphertext, (A1, A2), s)
            - m: The message.
            - ciphertext: The input ciphertext.
            - (A1, A2): Commitment points for the ZKP.
            - s: The response scalar.
    """
    # Extract ciphertext components
    ct_0, ct_1 = ciphertext

    # Convert integer message M to a point (M * G)
    m_point = m * pp[1]

    r = tc.number.random_in_range(1, pp[2])  # random nonce

    # A1 = r * g, A2 = r * C1
    commitment_ct_0 = r * pp[1]
    commitment_ct_1 = r * ct_0
    commitment_CT = (commitment_ct_0, commitment_ct_1)

    # V = C2 - M
    V = ct_1 + (-m_point)
    
    challenge = hash_to_int(pp[1], ek, ct_0, ct_1, m_point, V, commitment_ct_0, commitment_ct_1, order=pp[2])
    
    if isinstance(dk, list):
        dk = dk[0]
    else:
        dk = dk
    
    response = (r + challenge * dk) % pp[2]

    return (m, ciphertext, commitment_CT, response)

def verify_correct_decryption(ek, pp, proof):
    """
    Verify a Chaum–Pedersen style NIZK proof of correct decryption.

    Args:
        ek (ECC Point): ElGamal public key point.
        pp (tuple): Public parameters.
        proof (tuple): Proof structure returned by `prove_correct_decryption`.

    Returns:
        bool: True if the proof verifies, False otherwise.
    """
    
    M, CT, commitment_CT, s = proof
    ct_0, ct_1 = CT
    commitment_ct_0, commitment_ct_1 = commitment_CT
    
    m_point = M * pp[1]

    # V = C2 - M
    V = ct_1 + (-m_point)
    
    c = hash_to_int(pp[1], ek, ct_0, ct_1, m_point, V, commitment_ct_0, commitment_ct_1, order=pp[2])

    # check1: s * g == A1 + c * ek
    check1 = (s * pp[1] == commitment_ct_0 + (c * ek))

    # check2: s * C1 == A2 + c * V
    check2 = (s * ct_0 == commitment_ct_1 + (c * V))

    return check1 and check2


def prove_partial_decryption_share(pp, ct, key_share):
    """
    Creates a Chaum–Pedersen DLEQ proof for a single Threshold Partial Decryption share.

    Proves: log_g(E_i) == log_{C1}(D_i)

    Args:
        pp (tuple): Public parameters.
        ct (tuple): The ciphertext (C1, C2).
        key_share (tc.KeyShare): The object containing the secret scalar y_i.

    Returns:
        tuple: (A1, A2, z, ct1, D_i, share_commitment)
    """

    g = pp[1]
    order = pp[2]
    
    ct1, ct2 = ct
    
    ks0 = key_share
    y_i = ks0.y  # Secret key share
    share_commitment = int(y_i) * g  # E_i (public verification share)

    # Compute partial decryption share
    D_i = y_i * ct1

    # Commitments
    t = tc.number.random_in_range(1, order)
    A1 = t * g
    A2 = t * ct1

    # Challenge
    c = hash_to_int(
        g,
        share_commitment,  # E_i
        ct1,
        D_i,
        A1,
        A2,
        order=order
    )

    # Response
    z = (t + c * y_i) % order

    return (A1, A2, z, D_i, share_commitment)

def verify_partial_decryption_share(pp, ct, proof):
    """
    Verifies the ZKP for a partial decryption share.

    Checks:
      z * G  == A1 + c * E_i
      z * C1 == A2 + c * D_i

    Args:
        pp (tuple): Public parameters.
        ct1 (ECC Point): The C1 component of the ciphertext.
        proof (tuple): The proof object.

    Returns:
        bool: True if valid, False otherwise.
    """
    ct1, _ = ct
    g = pp[1]
    order = pp[2]
    A1, A2, z, D_i, share_commitment = proof

    # Recompute challenge
    c = hash_to_int(
        g,
        share_commitment,  # E_i
        ct1,
        D_i,
        A1,
        A2,
        order=order
    )

    # Check 1
    lhs1 = int(z) * g
    rhs1 = A1 + int(c) * share_commitment

    # Check 2
    lhs2 = int(z) * ct1
    rhs2 = A2 + int(c) * D_i

    return lhs1 == rhs1 and lhs2 == rhs2