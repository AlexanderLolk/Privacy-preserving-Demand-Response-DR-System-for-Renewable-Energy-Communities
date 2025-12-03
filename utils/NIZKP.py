import hashlib
import threshold_crypto as tc

def schnorr_NIZKP_challenge(elements):
    """Create a deterministic SHA-256 challenge from the provided elements.

    The function stringifies and length-prefixes each element, joins them
    with a separator and returns the raw SHA-256 digest. Callers usually
    convert the digest into an int and reduce modulo the group order.

    Args:
        elements (list): Sequence of values which will be stringified and
                         included in the challenge hash (strings or bytes).

    Returns:
        bytes: Raw SHA-256 digest to be interpreted by the caller.
    """
    elem = [len(elements)] + elements
    elem_str = map(str, elem)
    elem_len = map(lambda x: "%s||%s" % (len(x), x), elem_str)
    state = "|".join(elem_len)
    Hash = hashlib.sha256()
    Hash.update(state.encode("utf8"))
    return Hash.digest()

def schnorr_NIZKP_proof(pk, sec_params, sk, msg=""):
    """Create a Schnorr non-interactive proof of knowledge of `sk`.

    The proof demonstrates knowledge of the secret scalar `sk` such that
    `pk = sk * g` without revealing `sk`. It returns the tuple
    (challenge, response, commitment) where the challenge is derived via
    `schnorr_NIZKP_challenge` (Fiat–Shamir).

    Args:
        pk (ECC Point): Public key point corresponding to `sk`.
        sec_params (tc.CurveParameters): Curve parameters.
        sk (int): Secret scalar (private key).
        msg (str): Optional context string included in the challenge.

    Returns:
        tuple: (challenge (int), response (int), commitment (ECC Point)).
    """
    g = sec_params.P
    order = sec_params.order
    
    r = tc.number.random_in_range(1, order)  # nonce
    commitment = int(r) * g

    # Create challenge using point coordinates
    challenge_hash = schnorr_NIZKP_challenge([
        str(g.x), str(g.y),
        str(pk.x), str(pk.y),
        str(commitment.x), str(commitment.y),
        msg
    ])
    challenge = int.from_bytes(challenge_hash, "big") % int(order)
    response = (int(r) - int(challenge) * int(sk)) % int(order)
    return (challenge, response, commitment)

def schnorr_NIZKP_verify(pk, sec_params, proof, msg=""):
    """Verify a Schnorr NIZKP produced by `schnorr_NIZKP_proof`.

    The verifier reconstructs the commitment from the provided response
    and challenge, recomputes the Fiat–Shamir challenge and checks
    consistency.

    Args:
        pk (ECC Point): Public key point.
        sec_params (tc.CurveParameters): Curve parameters.
        proof (tuple): (challenge (int), response (int), commitment (ECC Point)).
        msg (str): Optional context string that must match the one used by
                   the prover.

    Returns:
        bool: True if the proof is valid, False otherwise.
    """
    g = sec_params.P
    order = sec_params.order
    c, s, W = proof
    
    # Reconstruct commitment: W_check = s * g + c * pk
    W_check = (int(s) * g) + (int(c) * pk)
    
    # Recompute challenge using reconstructed commitment
    challenge_hash = schnorr_NIZKP_challenge([
        str(g.x), str(g.y),
        str(pk.x), str(pk.y),
        str(W_check.x), str(W_check.y),
        msg
    ])
    check = int.from_bytes(challenge_hash, "big") % order
    
    return int(c) == check and W == W_check


def test_schnorr_NIZKP():
    """Test Schnorr NIZKP proof generation and verification."""
    print("=== Testing Schnorr NIZKP ===")
    
    # Setup
    pp = tc.CurveParameters("P-256")
    
    # Generate keypair
    print("1. Generating keypair...")
    sk = tc.number.random_in_range(1, pp.order)
    pk = sk * pp.P
    print(f"   Private key: {sk}")
    print(f"   Public key: {pk}")
    
    # Generate proof
    print("\n2. Generating NIZKP proof...")
    msg = "Test message"
    proof = schnorr_NIZKP_proof(pk, pp, sk, msg)
    c, s, W = proof
    print(f"   Challenge: {c}")
    print(f"   Response: {s}")
    print(f"   Commitment: {W}")
    
    # Verify proof
    print("\n3. Verifying proof...")
    is_valid = schnorr_NIZKP_verify(pk, pp, proof, msg)
    print(f"   Valid: {is_valid}")
    assert is_valid, "NIZKP verification failed!"
    
    # Test with wrong message
    print("\n4. Testing with wrong message...")
    wrong_msg = "Wrong message"
    is_valid_wrong = schnorr_NIZKP_verify(pk, pp, proof, wrong_msg)
    print(f"   Valid (should be False): {is_valid_wrong}")
    assert not is_valid_wrong, "NIZKP should not verify with wrong message!"
    
    # Test with tampered proof
    print("\n5. Testing with tampered proof...")
    tampered_proof = (c + 1, s, W)
    is_valid_tampered = schnorr_NIZKP_verify(pk, pp, tampered_proof, msg)
    print(f"   Valid (should be False): {is_valid_tampered}")
    assert not is_valid_tampered, "NIZKP should not verify with tampered proof!"
    
    print("\n=== All Schnorr NIZKP tests passed! ===\n")


if __name__ == "__main__":
    test_schnorr_NIZKP()