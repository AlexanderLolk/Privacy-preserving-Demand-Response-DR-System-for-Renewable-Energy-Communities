import utils.private_key_proof as sch
import threshold_crypto as tc

def test_schnorr_NIZKP():
    """Test Schnorr NIZKP proof generation and verification."""
    print("=== Testing Schnorr NIZKP ===")
    
    # Setup
    curve = tc.CurveParameters("P-256")
    g = curve.P
    order = curve.order
    pp = (curve, g, order)
    
    # Generate keypair
    print("1. Generating keypair...")
    sk = tc.number.random_in_range(2, order)
    pk = sk * g
    print(f"   Private key: {sk}")
    print(f"   Public key: {pk}")
    
    # Generate proof
    print("\n2. Generating NIZKP proof...")
    msg = "Test message"
    proof = sch.schnorr_NIZKP_proof(pk, pp, sk, msg)
    c, s, W = proof
    print(f"   Challenge: {c}")
    print(f"   Response: {s}")
    print(f"   Commitment: {W}")
    
    # Verify proof
    print("\n3. Verifying proof...")
    is_valid = sch.schnorr_NIZKP_verify(pk, pp, proof, msg)
    print(f"   Result (should be True): {is_valid}")
    assert is_valid, "NIZKP verification failed!"
    
    # Test with wrong message
    print("\n4. Testing with wrong message...")
    wrong_msg = "Wrong message"
    is_valid_wrong = sch.schnorr_NIZKP_verify(pk, pp, proof, wrong_msg)
    print(f"   Result (should be False): {is_valid_wrong}")
    assert not is_valid_wrong, "NIZKP should not verify with wrong message!"
    
    # Test with tampered proof
    print("\n5. Testing with tampered proof...")
    tampered_proof = (c + 1, s, W)
    is_valid_tampered = sch.schnorr_NIZKP_verify(pk, pp, tampered_proof, msg)
    print(f"   Result (should be False): {is_valid_tampered}")
    assert not is_valid_tampered, "NIZKP should not verify with tampered proof!"
    
    print("\n=== All Schnorr NIZKP tests passed! ===\n")

    
if __name__ == "__main__":
    test_schnorr_NIZKP()