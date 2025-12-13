import threshold_crypto as tc
from utils.signature import Signature
# test has been made with help from ai

def test_schnorr_signature():
    """Test Schnorr signature generation and verification."""
    print("=== Testing Schnorr Signature ===")
    sig = Signature()
    # Setup
    curve = tc.CurveParameters("P-256")
    g = curve.P
    order = curve.order
    pp = (curve, g, order)
    
    # Generate keypair
    print("1. Generating keypair...")
    sk_key, pk_key = sig.key_gen()
    
    # Extract scalar from private key for signing
    sk = sk_key
    # Convert public key point to threshold_crypto point
    pk_point = sk * g
    
    print(f"   Private key (scalar): {sk}")
    print(f"   Public key (point): {pk_point}")
    
    # Test single message signing
    print("\n2. Testing single message signing...")
    msg = "yo"
    print(f"   Message: {msg}")
    
    signature = sig.schnorr_sign(sk, pp, msg)
    R, s = signature
    print(f"   Signature R: {R}")
    print(f"   Signature s: {s}")
    
    # Verify signature
    print("\n3. Verifying signature...")
    is_valid = sig.schnorr_verify(pk_point, pp, msg, signature)
    print(f"   Valid: {is_valid}")
    assert is_valid, "Signature verification failed!"
    
    # Test with wrong message
    print("\n4. Testing with wrong message...")
    wrong_msg = "Wrong message"
    is_valid_wrong = sig.schnorr_verify(pk_point, pp, wrong_msg, signature)
    print(f"   Valid (should be False): {is_valid_wrong}")
    assert not is_valid_wrong, "Signature should not verify with wrong message!"
    
    # Test list signing
    print("\n5. Testing list signing...")
    msg_list = ["Message 1", "Message 2", "Message 3"]
    print(f"   Messages: {msg_list}")
    
    signatures = sig.schnorr_sign_list(sk, pp, msg_list)
    print(f"   Generated {len(signatures)} signatures")
    
    # Verify list
    print("\n6. Verifying signature list...")
    all_valid, results = sig.schnorr_verify_list(pk_point, pp, msg_list, signatures)
    print(f"   All valid: {all_valid}")
    for idx, msg, valid in results:
        print(f"   -    Message {idx}: '{msg}' -> {valid}")
    assert all_valid, "List signature verification failed!"
    
    # Test with one wrong message
    print("\n7. Testing list with one wrong message...")
    wrong_msg_list = ["Message 1", "Wrong message", "Message 3"]
    all_valid_wrong, results_wrong = sig.schnorr_verify_list(pk_point, pp, wrong_msg_list, signatures)
    print(f"   Only the second message should be false:")
    for idx, msg, valid in results_wrong:
        print(f"   -    Message {idx}: '{msg}' -> {valid}")
    assert not all_valid_wrong, "Should not verify with wrong messages!"
    
    print("\n=== All Schnorr signature tests passed! ===\n")

def test_key_gen():
    sig = Signature()
    sk_key, pk_key = sig.key_gen()
    print(f"Private Key: {sk_key}")
    print(f"Public Key x: {pk_key.x}, y: {pk_key.y}")

    print("\nGenerating another keypair:")
    sk_key, pk_key = sig.key_gen()
    print(f"Private Key: {sk_key}")
    print(f"Public Key x: {pk_key.x}, y: {pk_key.y}")

if __name__ == "__main__":
    test_key_gen()
    test_schnorr_signature()