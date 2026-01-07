import random
from src.utils.ec_elgamal import ElGamal
# test has been made with help from ai

def test_keygen(el):
    (ek, _), dk = el.keygen()
    # type of each:
    print("ek type: " + str(type(ek)))
    print("dk type: " + str(type(dk)))

    print("sk is: " + str(dk))
    print("ek -> x: " + str(ek.x) + ", y: " + str(ek.y))

def test_int_to_bytes_enc(el):
    msg = 0

    (ek, _), dk = el.keygen()

    encryptions = el.enc(ek, msg)

    message = el.dec(dk, encryptions)

    print("decrypted message: " + str(message))
        

def test_elgamal(el):
    (ek, _), dk = el.keygen()
    print("sk is: " + str(dk))
    print("pk is: " + str(ek))
    
    m = 123
    print("Original message (integer): " + str(m))
    
    cipher = el.enc(ek, m)
    print("Encrypted message: " + str(cipher))

    message_dec_int = el.dec(dk, cipher)
    print("Decrypted message (integer): " + str(message_dec_int))
    
    assert message_dec_int == m, f"expected {m}, got {message_dec_int}"

def test_elgamal_big_number(el):
    (ek, pp), dk = el.keygen()
    print("sk is: " + str(dk))
    print("pk is: " + str(ek))
    
    m = 700000000000067567567567567567567567667556756756756756767565342343212134543
    m_point = m * pp[1]
    print("Original message (integer): " + str(m))
    
    cipher = el.encrypt_single(ek, m)
    print("Encrypted message: " + str(cipher))

    message_dec_int = el.decrypt_single(dk, cipher)
    print("Decrypted message (integer): " + str(message_dec_int))
    
    assert message_dec_int == m_point, f"expected {m_point}, got {message_dec_int}"


def test_threshold_elgamal(el):
        
    pub_key, key_shares, thresh_params = el.keygen_threshold()

    m = 1

    encrypted_msg = el.enc(pub_key, m)
    print(f"Encrypted message: {len(encrypted_msg)} ciphertexts (one per bit)")

    print("key shares: " + str(key_shares))
    # Compute partial decryptions from each key share
    # Each returns a list of PartialDecryption objects, one per bit
    partial_from_share0 = el.partial_decrypt(encrypted_msg, key_shares[0])
    partial_from_share1 = el.partial_decrypt(encrypted_msg, key_shares[1])
    
    # Combine: interleave them so we have [share0_bit0, share0_bit1, ..., share1_bit0, share1_bit1, ...]
    partial_combined = partial_from_share0 + partial_from_share1
    
    print(f"Computed partial decryptions from {len(key_shares)} key shares")
    print(f"Total partial decryptions: {len(partial_combined)}")

    decrypted_msg = el.threshold_decrypt(partial_combined, encrypted_msg, thresh_params)
    print(f"Final decrypted message point: {decrypted_msg}")
    print(f"decrypted_msg: x = {decrypted_msg.x}, y = {decrypted_msg.y}")
    
    decrypted_msg = el._eval_threshold_decrypt(partial_combined, encrypted_msg)
    print(f"\nFinal decrypted message point: {decrypted_msg}")

def test_threshold_elgamal_on_target_reduction(el):
    pub_key, key_shares, thresh_params = el.keygen_threshold()
    
    m = [0, 0, 0, 10, 8, 5, 3, 0, 0, 0, 0, 7, 0, 4, 2, 6, 9, 1, 0]

    enc_tr = [el.enc(pub_key, val) for val in m]
    iden0 = 0 * el.pp[1]
    iden1 = 1 * el.pp[1]

    print(f"iden0: x = {iden0.x}, y = {iden0.y}")
    print(f"iden1: x = {iden1.x}, y = {iden1.y}")

    decrypted_point = []
    decrypted = []
    for list_of_cts in enc_tr:
        # list_of_cts [(ct1, ct2),......]
        partials_share0 = el.partial_decrypt(list_of_cts, key_shares[0])
        partials_share1 = el.partial_decrypt(list_of_cts, key_shares[1])
        combined_partials = partials_share0 + partials_share1
        
        plaintext_point = el.threshold_decrypt(combined_partials, list_of_cts, thresh_params)
        plaintext = el._eval_threshold_decrypt(combined_partials, list_of_cts)

        print(f"plaintext_point: x = {plaintext_point.x}, y = {plaintext_point.y}")
        
        decrypted_point.append(plaintext_point)
        decrypted.append(plaintext)

    for i in range(len(m)):
        assert m[i] == decrypted[i]

    print("all good") 

def test_threshold_elgamal_on_target_reduction_eval(el):
    pub_key, key_shares, thresh_params = el.keygen_threshold()
    
    m = [0, 0, 0, 10, 8, 5, 3, 0, 0, 0, 0, 7, 0, 4, 2, 6, 9, 1, 0]
    r = random.randint(1, el.pp[2])
    enc_tr = [el.enc(pub_key, val, r) for val in m]
    iden0 = 0 * el.pp[1]
    iden1 = 1 * el.pp[1]

    print(f"iden0: x = {iden0.x}, y = {iden0.y}")
    print(f"iden1: x = {iden1.x}, y = {iden1.y}")

    decrypted_point = []
    decrypted = []
    for list_of_cts in enc_tr:
        # list_of_cts [(ct1, ct2),......]
        partials_share0 = el.partial_decrypt(list_of_cts, key_shares[0])
        partials_share1 = el.partial_decrypt(list_of_cts, key_shares[1])
        combined_partials = partials_share0 + partials_share1
        
        plaintext_point = el.threshold_decrypt(combined_partials, list_of_cts, thresh_params)
        plaintext = el._eval_threshold_decrypt(combined_partials, list_of_cts)

        # print(f"plaintext_point: x = {plaintext_point.x}, y = {plaintext_point.y}")
        
        decrypted_point.append(plaintext_point)
        decrypted.append(plaintext)

    for i in range(len(m)):
        assert m[i] == decrypted[i]

    print("all good") 

def test_eval_threshold_elgamal(el):
        
    pub_key, key_shares, thresh_params = el.keygen_threshold()

    m = 12

    encrypted_msg = el.enc(pub_key, m)
    print(f"Encrypted message: {len(encrypted_msg)} ciphertexts (one per bit)")

    print("key shares: " + str(key_shares))
    # Compute partial decryptions from each key share
    partial_from_share0 = el.partial_decrypt(encrypted_msg, key_shares[0])
    partial_from_share1 = el.partial_decrypt(encrypted_msg, key_shares[1])
    
    # Combine: interleave them so we have [share0_bit0, share0_bit1, ..., share1_bit0, share1_bit1, ...]
    partial_combined = partial_from_share0 + partial_from_share1
    
    print(f"Computed partial decryptions from {len(key_shares)} key shares")
    print(f"Total partial decryptions: {len(partial_combined)}")

    decrypted_msg = el._eval_threshold_decrypt(partial_combined, encrypted_msg)
    print(f"Final decrypted message: {decrypted_msg}")

    assert decrypted_msg == m, f"Expected {m}, got {decrypted_msg}"

def test_threshold_elgamal_point(el):
    pub_key, key_shares, thresh_params = el.keygen_threshold()

    m = 12

    encrypted_msg = el.enc(pub_key, m)

    # Compute partial decryptions from each key share
    # Each returns a list of PartialDecryption objects, one per bit
    partial_from_share0 = el.partial_decrypt(encrypted_msg, key_shares[0])
    partial_from_share1 = el.partial_decrypt(encrypted_msg, key_shares[1])

    # encrypted_msg is:
    print(f"Encrypted message points: {encrypted_msg}")
    
    # Combine: interleave them so we have [share0_bit0, share0_bit1, ..., share1_bit0, share1_bit1, ...]
    partial_combined = partial_from_share0 + partial_from_share1
    
    print(f"Computed partial decryptions from {len(key_shares)} key shares")
    print(f"Total partial decryptions: {len(partial_combined)}")

    decrypted_msg = el.threshold_decrypt(partial_combined, encrypted_msg, thresh_params)

    print(f"Final decrypted message: {decrypted_msg}")

    msg_point = m * el.pp[1]
    
    assert decrypted_msg == msg_point, f"Expected {msg_point}, got {decrypted_msg}"
    print("Threshold ElGamal point decryption verified.")
    

def test_threshold_elgamal_deterministic_0(el):
        
    pub_key, key_shares, thresh_params = el.keygen_threshold()

    m = 0

    encrypted_msg = el.enc(pub_key, m, r=1)
    # print(f"Encrypted message: {len(encrypted_msg)} ciphertexts (one per bit)")
    deterministic_encryption_of_0 = el.enc(pub_key, 0, r=1)
    encrypted_of_0 = el.enc(pub_key, 0)
    
    assert deterministic_encryption_of_0 != encrypted_of_0, f"Something is wrong with deterministic encryption of 0"
    assert encrypted_msg == deterministic_encryption_of_0, f"Deterministic encryption of 0 failed"
    print("Deterministic encryption of 0 verified.")

    # Compute partial decryptions from each key share
    # Each returns a list of PartialDecryption objects, one per bit
    partial_from_share0 = el.partial_decrypt(encrypted_msg, key_shares[0])
    partial_from_share1 = el.partial_decrypt(encrypted_msg, key_shares[1])

    # encrypted_msg is:
    print(f"Encrypted message points: {encrypted_msg}")
    
    # Combine: interleave them so we have [share0_bit0, share0_bit1, ..., share1_bit0, share1_bit1, ...]
    partial_combined = partial_from_share0 + partial_from_share1
    
    print(f"Computed partial decryptions from {len(key_shares)} key shares")
    print(f"Total partial decryptions: {len(partial_combined)}")

    decrypted_msg = el.threshold_decrypt(partial_combined, encrypted_msg, thresh_params)
    print(f"Final decrypted message: {decrypted_msg}")
    msg_point = m * el.pp[1]

    # Compare point coordinates
    assert decrypted_msg == msg_point, f"Expected {msg_point}, got {decrypted_msg}"

def sub(el, c1, c2):
    """ Homomorphic subtraction of two encrypted lists of ciphertexts. """
    # Pad the shorter list to match lengths
    result = []
    for pair1, pair2 in zip(c1, c2):
        a1, b1 = pair1
        a2, b2 = pair2
        
        # Perform the ElGamal subtraction logic: (a1 - a2, b1 - b2)
        # Note: In many ElGamal implementations, subtraction is 
        # actually division, or addition of the inverse.
        result.append((a1 + (-a2), b1 + (-b2)))
    return result

def sub_as_integer(el, c1, c2):
    def collapse(cipher_list):
        total_a, total_b = None, None
        for i, (a, b) in enumerate(cipher_list):
            weight = 2**i
            # Scalar multiplication: weight * Point
            weighted_a = a * weight 
            weighted_b = b * weight
            
            if total_a is None:
                total_a, total_b = weighted_a, weighted_b
            else:
                total_a += weighted_a
                total_b += weighted_b
        return total_a, total_b

    int_ct1 = collapse(c1)
    int_ct2 = collapse(c2)

    res_a = int_ct1[0] + (-int_ct2[0])
    res_b = int_ct1[1] + (-int_ct2[1])
    return (res_a, res_b)


def test_sub(el):
    """ Test homomorphic subtraction of encrypted values using threshold encryption. """
    pub_key, key_shares, thresh_params = el.keygen_threshold()
    
    m1 = 125
    m2 = 8
    
    # Encrypt two messages
    cipher1 = el.enc(pub_key, m1)
    cipher2 = el.enc(pub_key, m2)
    
    print(f"Original message 1: {m1}")
    print(f"Original message 2: {m2}")
    
    print(f"Ciphertext 1 len: {len(cipher1)}")
    print(f"Ciphertext 2 len: {len(cipher2)}")
    
    # Perform homomorphic subtraction
    cipher_sub = sub_as_integer(el, cipher1, cipher2)
    
    # Decrypt the result using threshold decryption
    partial_from_share0 = el.partial_decrypt([cipher_sub], key_shares[0])
    partial_from_share1 = el.partial_decrypt([cipher_sub], key_shares[1])
    partial_combined = partial_from_share0 + partial_from_share1
    
    result = el.threshold_decrypt_point(partial_combined, cipher_sub)
    expected = (m1 * el.pp[1]) + (-(m2 * el.pp[1]))
    
    print(f"Decrypted result: {result}")
    print(f"Expected result: {expected}")
    
    assert result == expected, f"Expected {expected}, got {result}"
    print("Homomorphic subtraction with threshold encryption verified!")
    
    print(f"result is : x = {result.x}, y = {result.y}")
    print(f"expected is : x = {expected.x}, y = {expected.y}")



if __name__ == "__main__":
    el = ElGamal()
    # test_keygen(el)
    # test_int_to_bytes_enc(el)
    # test_elgamal(el)
    # test_elgamal_big_number(el)
    # test_threshold_elgamal(el)
    # test_threshold_elgamal_on_target_reduction(el)
    # test_threshold_elgamal_on_target_reduction_eval(el)
    # test_eval_threshold_elgamal(el)
    # test_threshold_elgamal_point(el)
    # test_threshold_elgamal_deterministic_0(el)
    test_sub(el)