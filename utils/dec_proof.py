

from utils.ec_elgamal import ElGamal
import hashlib
import threshold_crypto as tc

def hash_to_int(*points, order):
    """Hash EC points deterministically into a scalar mod q."""
    h = hashlib.sha256()
    for P in points:
        if hasattr(P, "x") and hasattr(P, "y"):
            h.update(int(P.x).to_bytes(32, "big"))
            h.update(int(P.y).to_bytes(32, "big"))
        else:
            h.update(str(P).encode())
    return int.from_bytes(h.digest(), "big") % int(order)

def prove_correct_decryption(ek, pp, m, dk, ciphertext):
    """Prove that M = C2 - dk * C1 (i.e., correct ElGamal decryption)
    without revealing dk.
    Returns a non-interactive proof (A1, A2, s).

    Args:
        ek (ECC Point): ElGamal public key point (ek = dk * g).
        sec_params (tc.CurveParameters): Curve parameters.
        M (int): Message as an integer.
        dk (int): Secret key scalar corresponding to `ek`.
        ciphertext (tuple): (C1, C2) ElGamal ciphertext pair.

    Returns:
        tuple: (m_point, CT, (A1, A2), s)
            - m_point (ECC Point): the message as an EC point
            - CT (tuple): ciphertext pair (C1, C2)
            - (A1, A2) (tuple): commitment points
            - s (int): response scalar for the NIZK
    """
    
    # Extract ciphertext components
    ct_0, ct_1 = ciphertext


    m_point = m * pp[1]

    r = tc.number.random_in_range(1, pp[2])  # random nonce

    # A1 = r * g, A2 = r * C1
    commitment_ct_0 = int(r) * pp[1]
    commitment_ct_1 = int(r) * ct_0
    commitment_CT = (commitment_ct_0, commitment_ct_1)

    # V = C2 - M
    V = ct_1 + (-m_point)
    
    challenge = hash_to_int(pp[1], ek, ct_0, ct_1, m_point, V, commitment_ct_0, commitment_ct_1, order=pp[2])
    
    # Ensure dk is an integer
    if isinstance(dk, list):
        dk = dk[0]
    # if hasattr(dk, "d"):
    #     dk = int(dk.d)
    else:
        dk = int(dk)
    
    response = (int(r) + int(challenge) * dk) % pp[2]

    return (m_point, ciphertext, commitment_CT, response)

def verify_correct_decryption(ek, pp, proof):
    """Verify a Chaum–Pedersen style NIZK proof of correct decryption.

    Args:
        ek (ECC Point): ElGamal public key point.
        sec_params (tc.CurveParameters): Curve parameters.
        proof (tuple): Proof returned by `prove_correct_decryption`.

    Returns:
        bool: True if the proof verifies, False otherwise.
    """
    
    M, CT, commitment_CT, s = proof
    ct_0, ct_1 = CT
    commitment_ct_0, commitment_ct_1 = commitment_CT
    
    
    m_point = int(M) * pp[1]

    # V = C2 - M
    V = ct_1 + (-m_point)
    
    c = hash_to_int(pp[1], ek, ct_0, ct_1, m_point, V, commitment_ct_0, commitment_ct_1, order=pp[2])

    # check1: s * g == A1 + c * ek
    check1 = (int(s) * pp[1] == commitment_ct_0 + (int(c) * ek))

    # check2: s * C1 == A2 + c * V
    check2 = (int(s) * ct_0 == commitment_ct_1 + (int(c) * V))

    return check1 and check2


def prove_partial_decryption_share(pp, ct, key_share):
    """
    Create a Chaum–Pedersen DLEQ proof for a threshold decryption share.

    Proves:  log_g(E_i) = log_{C1}(D_i)
    where:
        E_i = y_i*g        (commitment)
        D_i = y_i*C1       (partial decryption)

    Returns:
        (D_i, proof=(A1, A2, z))
    """

    g = pp[1]
    order = pp[2]
    
    ct1, ct2 = ct
    
    ks0 = key_share
    y_i = ks0.y  # Secret key share
    share_commitment = int(y_i) * g  # E_i 

    # Compute partial decryption share
    D_i = y_i * ct1

    # --- Chaum–Pedersen commitment ---
    t = tc.number.random_in_range(1, order)
    A1 = t * g
    A2 = t * ct1

    # --- Fiat–Shamir challenge ---
    c = hash_to_int(
        g,
        share_commitment,  # E_i
        ct1,
        D_i,
        A1,
        A2,
        order=order
    )

    # --- Response ---
    z = (t + c * y_i) % order

    return (A1, A2, z, ct1, D_i, share_commitment)

def verify_partial_decryption_share(pp, proof):
    """
    Verify Chaum–Pedersen DLEQ proof for a single partial decryption share.

    Checks:
      z*g == A1 + c*E_i
      z*C1 == A2 + c*D_i

    Returns:
        True / False
    """

    g = pp[1]
    order = pp[2]
    A1, A2, z, ct1, D_i, share_commitment = proof

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

def test_dec_proof():
    """Test decryption proof generation and verification."""
    print("=== Testing Decryption Proof ===")
    
    # Setup
    elgamal = ElGamal("P-256")
    
    # Generate keypair
    print("1. Generating ElGamal keypair...")
    (ek, pp), dk = elgamal.keygen()
    print(f"   Secret key: {dk}")
    print(f"   Public key: {ek}")
    
    # Encrypt a message
    print("\n2. Encrypting message...")
    m = 42
    print(f"   Message: {m}")
    ciphertext = elgamal.encrypt_single(ek, m)
    print(f"   Ciphertext: {ciphertext}")
    
    # Generate proof
    print("\n3. Generating decryption proof...")
    proof = prove_correct_decryption(ek, pp, m, dk, ciphertext)
    print(f"   Proof generated")
    
    # Verify proof
    print("\n4. Verifying proof...")
    is_valid = verify_correct_decryption(ek, pp, proof)
    print(f"   Valid: {is_valid}")
    assert is_valid, "Decryption proof verification failed!"
    
    print("\n=== All decryption proof tests passed! ===\n")


def test_partial_decryption_share_proof():
    """Test DLEQ proof for partial decryption share."""
    print("=== Testing Partial Decryption Share Proof ===")
    
    # Setup
    elgamal = ElGamal("P-256")
    
    # Generate threshold keypair
    print("1. Generating threshold ElGamal keypair")
    pub_key, key_shares, thresh_params = elgamal.keygen_threshold()
    
    # Encrypt a message
    print("\n2. Encrypting message")
    m = 42
    ciphertext = elgamal.encrypt_single(pub_key, m)


    print("\n3. Generating partial decryption share proof")
    proof = prove_partial_decryption_share(elgamal.pp, ciphertext, key_shares[0])

    print("\n4. Verifying partial decryption share proof")
    is_valid = verify_partial_decryption_share(elgamal.pp, proof)
    print(f"   Valid: {is_valid}")
    assert is_valid, "Partial decryption share proof verification failed!"


if __name__ == "__main__":
    # test_dec_proof()
    test_partial_decryption_share_proof()