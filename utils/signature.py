import hashlib
from Crypto.PublicKey import ECC
import threshold_crypto as tc

def key_gen(curve_name="P-256"):
    key = ECC.generate(curve=curve_name)
    return key.d, key.public_key().pointQ

def point_to_bytes(point):
    if hasattr(point, 'export'):
        # threshold_crypto point
        return point.export()
    elif hasattr(point, 'x') and hasattr(point, 'y'):
        # Crypto.PublicKey.ECC.EccPoint
        x_bytes = point.x.to_bytes(32, 'big')
        y_bytes = point.y.to_bytes(32, 'big')
        return x_bytes + y_bytes
    else:
        raise TypeError(f"Unsupported point type: {type(point)}")

def Hash(R, msg, order):
    h = hashlib.sha256()
    
    # Hash the point R
    h.update(point_to_bytes(R))

    # Convert msg to bytes based on its type (doing them all for now because of earlier code said so)
    if isinstance(msg, bytes):
        msg_bytes = msg
    elif isinstance(msg, int):
        msg_bytes = msg.to_bytes((msg.bit_length() + 7) // 8, 'big') # its +7 because it rounds up to nearest byte and //
    elif hasattr(msg, 'x') and hasattr(msg, 'y'):
        # It's a point
        msg_bytes = point_to_bytes(msg)
    else:
        msg_bytes = str(msg).encode()

    h.update(msg_bytes)
    digest_bytes = h.digest()
    digest_int = int.from_bytes(digest_bytes, 'big')
    return digest_int % order

def schnorr_sign(sk, pp, msg):
    
    g = pp[1]
    order = pp[2]
    
    k = tc.number.random_in_range(1, order)
    ephemeral_key = k * g
    challenge_hash = Hash(ephemeral_key, msg, order)

    signature = (int(k) + int(sk) * int(challenge_hash)) % int(order)
    return (ephemeral_key, signature)

def schnorr_verify(pk, pp, msg, signature):
    g = pp[1]
    order = pp[2]
    R, s = signature
    
    e = Hash(R, msg, order)

    expected_point = int(s) * g
    reconstructed_point = R + int(e) * pk

    return expected_point == reconstructed_point

#
def schnorr_sign_list(sk, pp, msg_list):
    signatures = []
    for msg in msg_list:
        sign = schnorr_sign(sk, pp, msg)
        signatures.append(sign)
    return signatures

def schnorr_verify_list(pk, pp, msg_list, signatures):
    results = []
    for i, (msg, signature) in enumerate(zip(msg_list, signatures)):
        is_valid = schnorr_verify(pk, pp, msg, signature)
        if not is_valid:
            results.append((i, msg, False))
        else:
            results.append((i, msg, True))
    
    all_valid = all(r[2] for r in results)
    return (all_valid, results)

def test_schnorr_signature():
    """Test Schnorr signature generation and verification."""
    print("=== Testing Schnorr Signature ===")
    
    # Setup
    curve = tc.CurveParameters("P-256")
    g = curve.P
    order = curve.order
    pp = (curve, g, order)
    
    # Generate keypair
    print("1. Generating keypair...")
    sk_key, pk_key = key_gen("P-256")
    
    # Extract scalar from private key for signing
    sk = sk_key.d
    # Convert public key point to threshold_crypto point
    pk_point = sk * g
    
    print(f"   Private key (scalar): {sk}")
    print(f"   Public key (point): {pk_point}")
    
    # Test single message signing
    print("\n2. Testing single message signing...")
    msg = "yo"
    print(f"   Message: {msg}")
    
    signature = schnorr_sign(sk, pp, msg)
    R, s = signature
    print(f"   Signature R: {R}")
    print(f"   Signature s: {s}")
    
    # Verify signature
    print("\n3. Verifying signature...")
    is_valid = schnorr_verify(pk_point, pp, msg, signature)
    print(f"   Valid: {is_valid}")
    assert is_valid, "Signature verification failed!"
    
    # Test with wrong message
    print("\n4. Testing with wrong message...")
    wrong_msg = "Wrong message"
    is_valid_wrong = schnorr_verify(pk_point, pp, wrong_msg, signature)
    print(f"   Valid (should be False): {is_valid_wrong}")
    assert not is_valid_wrong, "Signature should not verify with wrong message!"
    
    # Test list signing
    print("\n5. Testing list signing...")
    msg_list = ["Message 1", "Message 2", "Message 3"]
    print(f"   Messages: {msg_list}")
    
    signatures = schnorr_sign_list(sk, pp, msg_list)
    print(f"   Generated {len(signatures)} signatures")
    
    # Verify list
    print("\n6. Verifying signature list...")
    all_valid, results = schnorr_verify_list(pk_point, pp, msg_list, signatures)
    print(f"   All valid: {all_valid}")
    for idx, msg, valid in results:
        print(f"   Message {idx}: '{msg}' -> {valid}")
    assert all_valid, "List signature verification failed!"
    
    # Test with one wrong message
    print("\n7. Testing list with one wrong message...")
    wrong_msg_list = ["Message 1", "Wrong message", "Message 3"]
    all_valid_wrong, results_wrong = schnorr_verify_list(pk_point, pp, wrong_msg_list, signatures)
    print(f"   All valid (should be False): {all_valid_wrong}")
    for idx, msg, valid in results_wrong:
        print(f"   Message {idx}: '{msg}' -> {valid}")
    assert not all_valid_wrong, "Should not verify with wrong messages!"
    
    print("\n=== All Schnorr signature tests passed! ===\n")

def test_key_gen():
    sk_key, pk_key = key_gen("P-256")
    print(f"Private Key: {sk_key}")
    print(f"Public Key x: {pk_key.x}, y: {pk_key.y}")

    print("\nGenerating another keypair:")
    sk_key, pk_key = key_gen("P-256")
    print(f"Private Key: {sk_key}")
    print(f"Public Key x: {pk_key.x}, y: {pk_key.y}")



if __name__ == "__main__":
    test_key_gen()
    # test_schnorr_signature()