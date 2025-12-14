from src.utils.ec_elgamal import ElGamal
import src.utils.elgamal_dec_proof as dec
# test has been made with help from ai

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
    proof = dec.prove_correct_decryption(ek, pp, m, dk, ciphertext)
    print(f"   Proof generated")
    
    # Verify proof
    print("\n4. Verifying proof...")
    is_valid = dec.verify_correct_decryption(ek, pp, proof)
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
    proof = dec.prove_partial_decryption_share(elgamal.pp, ciphertext, key_shares[0])

    print("\n4. Verifying partial decryption share proof")
    is_valid = dec.verify_partial_decryption_share(elgamal.pp, ciphertext, proof)
    print(f"   Valid: {is_valid}")
    assert is_valid, "Partial decryption share proof verification failed!"

if __name__ == "__main__":
    test_dec_proof()
    test_partial_decryption_share_proof()