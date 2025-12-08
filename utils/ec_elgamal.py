import threshold_crypto as tc
from Crypto.PublicKey import ECC

# params for threshold_crypto
# G                 = ECC._curves[curve_name]
# g                 = curve_params.P 
# order             = curve_par ams.order
# order.random()    = number.random_in_range(1, curve_params.order) AKA d
# pk                = Q
# sk                = d

class ElGamal:

    def __init__(self, curve="P-256"):
        if isinstance(curve, str):
            self.curve = tc.CurveParameters(curve)
            g = self.curve.P
            order = self.curve.order
            self.pp = (self.curve, g, order)
        else:
            self.curve = curve[0]
            self.pp = (curve[0], curve[1], curve[2])
            
    def keygen(self, pp=None):
        """
        # 
        """
        x = tc.number.random_in_range(2, self.pp[2])
        ek = x * self.pp[1]
        dk = x
        return ((ek, self.pp), dk) 

    def _int_to_bits(self, message: int):
        if message == 0:
            return [0]

        length = message.bit_length()
        # print("bit_length for message: " + str(length))
        list_bits = []

        # Extracts the bit at position i
        # Example: n = 13 (1101) & i = 2
        # (13 >> 2) = (1101) >> 2 = 3 (0011)
        # 3 (0011) & 1 (0001) = 1 (0001)
        for i in reversed(range(length)):
            # print((message >> i) & 1)
            list_bits.append(((message >> i) & 1))

        return list_bits
    
    def _bits_to_int(self, bits: list):
        message = 0
        # print("bits: " + str(bits))
        for bit in bits:
            # Append one bit to the right side of the number
            # example: wants to add 0101 into message
            #   message = (message << 1) | 1   # 0000 -> 0001 (1)
            #   message = (message << 1) | 0   # 0001 -> 0010 (2)
            #   message = (message << 1) | 1   # 0010 -> 0101 (5)
            #   result: 5 (0101)
            # print(bit)
            message = (message << 1) | bit

            # print("Added bit " + str(bit) + " to message")
            # print("message is now: " + str(bin(message)[2:]))
            # print("Number: " + str(message) + "\n")
        return message


    def encrypt_single(self, encryption_key: ECC.EccPoint, message: int):
        """
        """
        
        r = tc.number.random_in_range(2, self.pp[2])
    
        if isinstance(message, int):
            message = message * self.pp[1]


        c1 = r * self.pp[1]
        c2 = (r * encryption_key) + message
        
        return [c1, c2]
    
    def enc(self, encryption_key: ECC.EccPoint, message: int, r=None):
        """
        """
        
        if r is None:
            r = tc.number.random_in_range(2, self.pp[2])
        
        list_bits = self._int_to_bits(message)
        encryptions = []
        for bit in list_bits:
            bit_point = bit * self.pp[1]
            c1 = r * self.pp[1]
            c2 = (r * encryption_key) + bit_point
            encryptions.append((c1, c2))

        return encryptions
    
    def _check_if_zero_or_one(self, message_points: list):
        """
        """
        one_point = 1 * self.pp[1]
        message_bits = []
        for point in  message_points:
            if point == one_point:
                message_bits.append(1)
            else:
                message_bits.append(0)

        return message_bits
            
    def decrypt_single(self, secret_key, ciphertext):
        """
        """
        c1 = ciphertext[0]
        c2 = ciphertext[1]
        s = (self.pp[2] + -secret_key) * c1
        s2 = c2 + s
        return self._check_if_zero_or_one(s2)
    
    def dec(self, secret_key, ciphertexts):
        """
        """
        point_messages = []
        for ciphertext in ciphertexts:
            c1 = ciphertext[0]
            c2 = ciphertext[1]
            
            mol_inv = self.pp[2] + -secret_key
            s = mol_inv * c1
            message_point = c2 + s
            
            point_messages.append(message_point)
        list_bits = self._check_if_zero_or_one(point_messages)
        return self._bits_to_int(list_bits)
        
    # threshold partial decryption
    def keygen_threshold(self, pp=None):
        """
        """
        
        thresh_params = tc.ThresholdParameters(2, 2)
        encryption_key, key_shares = tc.create_public_key_and_shares_centralized(self.pp[0], thresh_params)
        
        self.thresh_params = thresh_params
        
        # encryption_key.Q = ek
        return encryption_key.Q, key_shares, thresh_params
    
    # def partial_threshold_decrypt(self, encrypted_message, key_share):
    #     encrypted_message = tc.EncryptedMessage(encrypted_message[0], encrypted_message[0], bytes(1))
    #     return tc.compute_partial_decryption(encrypted_message, key_share)

    # def decrypt_threshold(self, partial_decryptions, encrypted_message, thres_params):
    #     return tc.decrypt_message(partial_decryptions, encrypted_message, thres_params)
    
    def partial_decrypt(self, ciphertexts, key_share: tc.KeyShare):
        """
        """
        list_PartialDecryptions = []
        for ciphertext in ciphertexts:
            c1 = ciphertext[0]
            v_y = c1 * key_share.y
            list_PartialDecryptions.append(tc.PartialDecryption(key_share.x, v_y, self.curve))
        
        return list_PartialDecryptions
    
    def threshold_decrypt(
        self,
        partial_decryptions: list,
        encrypted_message: list,
        threshold_params: tc.ThresholdParameters,
    ):
        """
            Combines multiple partial decryptions to obtain the original message.
            encrypted_message is a list of (c1, c2) tuples, one for each bit.
            partial_decryptions is a flat list of PartialDecryption objects from all key shares and all bits.
            We need to organize them: group by bit index first, then by key share.
        """
        
        num_bits = len(encrypted_message)
        print("num_bit: " + str(num_bits))
        num_shares = len(partial_decryptions) // num_bits
        print(f"Number of bits: {num_bits}, Number of shares: {num_shares}")
        
        # Changing partial_decryptions from [share0_bit0, share0_bit1, ..., share1_bit0, share1_bit1, ...]
        # to [[share0_bit0, share1_bit0], [share0_bit1, share1_bit1], ...]
        partial_by_bit = []
        for i in range(num_bits):
            bit_partials = []
            for share_i in range(num_shares):
                pd = partial_decryptions[share_i * num_bits + i]
                # print(f"partial_decryptions[{share_i * num_bits + i}]")
                bit_partials.append(pd)
            
            # [share0_bit0, share1_bit0]
            partial_by_bit.append(bit_partials)
        
        # Decrypt each bit position
        decrypted_bits = []
        for i, bit_partials in enumerate(partial_by_bit):
            c1, c2 = encrypted_message[i]
            
            partial_indices = [dec.x for dec in bit_partials]
            # Report:
            # Lagrange coefficients are used to combine the partial decryptions from key shares to
            # reconstruct the decryption key (or its effect) and thus recover the original message.
            lagrange_coefficients = [
                tc.lagrange_coefficient_for_key_share_indices(
                    partial_indices, idx, self.curve
                )
                for idx in partial_indices
            ]
            
            # Compute sum of Lagrange-weighted partial decryptions for this bit
            # Lagrange interpolation is a mathematical technique used to reconstruct a secret from multiple shares.
            summands = [
                (lagrange_coefficients[i].coefficient * bit_partials[i].yC1)
                for i in range(0, len(bit_partials))
            ]
            
            # homomorphic property
            accumulated_point = tc.number.ecc_sum(summands)
            # print(f"Bit {i}: restored_kdP = {accumulated_point}")
            
            # Recover the message point: M = C2 - (nonce * decryption key * g) where (...) is the sum in accumulated_point
            restored_point = c2 + (-accumulated_point)
            
            bit = self._check_if_zero_or_one([restored_point])[0]
            # print(f"Bit {i}: recovered bit = {bit}")
            decrypted_bits.append(bit)
        
        # Convert bits back to integer
        decrypted_message = self._bits_to_int(decrypted_bits)

        decrypted_message_point = decrypted_message * self.pp[1] 
        
        # print(f"Decrypted message: {decrypted_message}, Expected: {expected_value}")

        return decrypted_message_point
    
    # this or a ZK range proof
    def _eval_threshold_decrypt(
        self,
        partial_decryptions: list,
        encrypted_message: list,
    ):
        """
            Combines multiple partial decryptions to obtain the original message.
            encrypted_message is a list of (c1, c2) tuples, one for each bit.
            partial_decryptions is a flat list of PartialDecryption objects from all key shares and all bits.
            We need to organize them: group by bit index first, then by key share.
        """
        
        num_bits = len(encrypted_message)
        # print("num_bit: " + str(num_bits))
        num_shares = len(partial_decryptions) // num_bits
        # print(f"Number of bits: {num_bits}, Number of shares: {num_shares}")
        
        # Changing partial_decryptions from [share0_bit0, share0_bit1, ..., share1_bit0, share1_bit1, ...]
        # to [[share0_bit0, share1_bit0], [share0_bit1, share1_bit1], ...]
        partial_by_bit = []
        for i in range(num_bits):
            bit_partials = []
            for share_i in range(num_shares):
                pd = partial_decryptions[share_i * num_bits + i]
                # print(f"partial_decryptions[{share_i * num_bits + i}]")
                bit_partials.append(pd)
            
            # [share0_bit0, share1_bit0]
            partial_by_bit.append(bit_partials)
        
        # Decrypt each bit position
        decrypted_bits = []
        for i, bit_partials in enumerate(partial_by_bit):
            c1, c2 = encrypted_message[i]
            
            partial_indices = [dec.x for dec in bit_partials]
            # Report:
            # Lagrange coefficients are used to combine the partial decryptions from key shares to
            # reconstruct the decryption key (or its effect) and thus recover the original message.
            lagrange_coefficients = [
                tc.lagrange_coefficient_for_key_share_indices(
                    partial_indices, idx, self.curve
                )
                for idx in partial_indices
            ]
            
            # Compute sum of Lagrange-weighted partial decryptions for this bit
            # Lagrange interpolation is a mathematical technique used to reconstruct a secret from multiple shares.
            summands = [
                (lagrange_coefficients[i].coefficient * bit_partials[i].yC1)
                for i in range(0, len(bit_partials))
            ]
            
            # homomorphic property
            accumulated_point = tc.number.ecc_sum(summands)
            # print(f"Bit {i}: restored_kdP = {accumulated_point}")
            
            # Recover the message point: M = C2 - (nonce * decryption key * g) where (...) is the sum in accumulated_point
            restored_point = c2 + (-accumulated_point)
            
            bit = self._check_if_zero_or_one([restored_point])[0]
            # print(f"Bit {i}: recovered bit = {bit}")
            decrypted_bits.append(bit)
        
        # Convert bits back to integer
        decrypted_message = self._bits_to_int(decrypted_bits)
        
        # print(f"Decrypted message: {decrypted_message}, Expected: {expected_value}")

        return decrypted_message

    ###
    # tests
    ###
    def test_keygen(self):
        (ek, _), dk = self.keygen()
        # type of each:
        print("ek type: " + str(type(ek)))
        print("dk type: " + str(type(dk)))

        print("sk is: " + str(dk))
        print("ek -> x: " + str(ek.x) + ", y: " + str(ek.y))

    def test_int_to_bytes_enc(self):
        msg = 0
        # binary_string = f'{msg:b}'
        # print("msg to bits: " + binary_string)

        # self.int_to_bits(msg)
        (ek, _), dk = self.keygen()
        # ek, dks = self.keygen_threshold()
        encryptions = self.enc(ek, msg)
        # print(str(encryptions))
        message = self.dec(dk, encryptions)
        print("decrypted message: " + str(message))
        # ek, dk = self.keygen()
        # cipher = self.encrypt(ek, msg)
        # message_dec_int = self.decrypt(dk, cipher, msg)
        # assert msg == message_dec_int
         

    def test_elgamal(self):
        (ek, _), dk = self.keygen()
        print("sk is: " + str(dk))
        print("pk is: " + str(ek))
        
        m = 123
        print("Original message (integer): " + str(m))
        
        cipher = self.enc(ek, m)
        print("Encrypted message: " + str(cipher))
    
        message_dec_int = self.dec(dk, cipher)
        print("Decrypted message (integer): " + str(message_dec_int))
        
        assert message_dec_int == m, f"expected {m}, got {message_dec_int}"


    def test_threshold_elgamal(self):
            
        pub_key, key_shares, thresh_params = self.keygen_threshold()
        # print("Generated 2-of-2 threshold keys")

        m = 1
        # print(f"Original message: {m}")

        encrypted_msg = self.enc(pub_key, m)
        print(f"Encrypted message: {len(encrypted_msg)} ciphertexts (one per bit)")

        print("key shares: " + str(key_shares))
        # Compute partial decryptions from each key share
        # Each returns a list of PartialDecryption objects, one per bit
        partial_from_share0 = self.partial_decrypt(encrypted_msg, key_shares[0])
        partial_from_share1 = self.partial_decrypt(encrypted_msg, key_shares[1])
        
        # Combine: interleave them so we have [share0_bit0, share0_bit1, ..., share1_bit0, share1_bit1, ...]
        partial_combined = partial_from_share0 + partial_from_share1
        
        print(f"Computed partial decryptions from {len(key_shares)} key shares")
        print(f"Total partial decryptions: {len(partial_combined)}")

        decrypted_msg = self.threshold_decrypt(partial_combined, encrypted_msg, thresh_params)
        print(f"Final decrypted message point: {decrypted_msg}")
        print(f"decrypted_msg: x = {decrypted_msg.x}, y = {decrypted_msg.y}")
        
        decrypted_msg = self._eval_threshold_decrypt(partial_combined, encrypted_msg)
        print(f"\nFinal decrypted message point: {decrypted_msg}")

        # assert decrypted_msg == m, f"Expected {m}, got {decrypted_msg}"

    def test_threshold_elgamal_sub(self):
            
        pub_key, key_shares, thresh_params = self.keygen_threshold()
        # print("Generated 2-of-2 threshold keys")

        m = 18
        # print(f"Original message: {m}")
        sub_m = 9

        encrypted_msg = self.enc(pub_key, m)

        encrypted_msg_sub = self.enc(pub_key, sub_m)

        print(f"Encrypted message: {len(encrypted_msg)} ciphertexts (one per bit)")
        print(f"Encrypted sub message: {len(encrypted_msg_sub)} ciphertexts (one per bit)")

        combind = []
        for i in range(len(encrypted_msg)):
            c1_m, c2_m = encrypted_msg[i]
            c1_sub, c2_sub = encrypted_msg_sub[i]
            combind.append((c1_m + (-c1_sub), c2_m + (-c2_sub)))

        print("key shares: " + str(key_shares))
        # Compute partial decryptions from each key share
        # Each returns a list of PartialDecryption objects, one per bit
        partial_from_share0 = self.partial_decrypt(combind, key_shares[0])
        partial_from_share1 = self.partial_decrypt(combind, key_shares[1])
        
        # Combine: interleave them so we have [share0_bit0, share0_bit1, ..., share1_bit0, share1_bit1, ...]
        partial_combined = partial_from_share0 + partial_from_share1
        
        print(f"Computed partial decryptions from {len(key_shares)} key shares")
        print(f"Total partial decryptions: {len(partial_combined)}")

        decrypted_msg = self.threshold_decrypt(partial_combined, combind, thresh_params)
        print(f"Final decrypted message point: {decrypted_msg}")
        print(f"decrypted_msg: x = {decrypted_msg.x}, y = {decrypted_msg.y}")
        
        decrypted_msg = self._eval_threshold_decrypt(partial_combined, combind)
        print(f"\nFinal decrypted message point: {decrypted_msg}")
        assert decrypted_msg == m - sub_m, f"Expected {m - sub_m}, got {decrypted_msg}"
    

    def test_threshold_elgamal_on_target_reduction(self):
        pub_key, key_shares, thresh_params = self.keygen_threshold()
        
        m = [0, 0, 0, 10, 8, 5, 3, 0, 0, 0, 0, 7, 0, 4, 2, 6, 9, 1, 0]
        # m = [1, 0, 0, 1, 0]

        enc_tr = [self.enc(pub_key, val) for val in m]
        iden0 = 0 * self.pp[1]
        iden1 = 1 * self.pp[1]

        print(f"iden0: x = {iden0.x}, y = {iden0.y}")
        print(f"iden1: x = {iden1.x}, y = {iden1.y}")

        decrypted_point = []
        decrypted = []
        for list_of_cts in enc_tr:
            # list_of_cts [(ct1, ct2),......]
            # print(f"list_of_cts = {list_of_cts}")
            partials_share0 = self.partial_decrypt(list_of_cts, key_shares[0])
            partials_share1 = self.partial_decrypt(list_of_cts, key_shares[1])
            combined_partials = partials_share0 + partials_share1
            
            plaintext_point = self.threshold_decrypt(combined_partials, list_of_cts, thresh_params)
            plaintext = self._eval_threshold_decrypt(combined_partials, list_of_cts)

            print(f"plaintext_point: x = {plaintext_point.x}, y = {plaintext_point.y}")
            
            # assert (plaintext_point.x == iden0.x and plaintext_point.y == iden0.y) or (plaintext_point.y == iden1.y and plaintext_point.x == iden1.x)
            decrypted_point.append(plaintext_point)
            decrypted.append(plaintext)

        for i in range(len(m)):
            assert m[i] == decrypted[i]

        print("all good") 

    def test_threshold_elgamal_on_target_reduction_eval(self):
        pub_key, key_shares, thresh_params = self.keygen_threshold()
        
        m = [0, 0, 0, 10, 8, 5, 3, 0, 0, 0, 0, 7, 0, 4, 2, 6, 9, 1, 0]
        # m = [1, 0, 0, 1, 0]

        enc_tr = [self.enc(pub_key, val) for val in m]
        iden0 = 0 * self.pp[1]
        iden1 = 1 * self.pp[1]

        print(f"iden0: x = {iden0.x}, y = {iden0.y}")
        print(f"iden1: x = {iden1.x}, y = {iden1.y}")

        decrypted_point = []
        decrypted = []
        for list_of_cts in enc_tr:
            # list_of_cts [(ct1, ct2),......]
            # print(f"list_of_cts = {list_of_cts}")
            partials_share0 = self.partial_decrypt(list_of_cts, key_shares[0])
            partials_share1 = self.partial_decrypt(list_of_cts, key_shares[1])
            combined_partials = partials_share0 + partials_share1
            
            plaintext_point = self.threshold_decrypt(combined_partials, list_of_cts, thresh_params)
            plaintext = self._eval_threshold_decrypt(combined_partials, list_of_cts)

            print(f"plaintext_point: x = {plaintext_point.x}, y = {plaintext_point.y}")
            
            # assert (plaintext_point.x == iden0.x and plaintext_point.y == iden0.y) or (plaintext_point.y == iden1.y and plaintext_point.x == iden1.x)
            decrypted_point.append(plaintext_point)
            decrypted.append(plaintext)

        for i in range(len(m)):
            assert m[i] == decrypted[i]

        print("all good") 



    def test_eval_threshold_elgamal(self):
            
        pub_key, key_shares, thresh_params = self.keygen_threshold()
        # print("Generated 2-of-2 threshold keys")

        m = 12
        # print(f"Original message: {m}")

        encrypted_msg = self.enc(pub_key, m)
        print(f"Encrypted message: {len(encrypted_msg)} ciphertexts (one per bit)")

        print("key shares: " + str(key_shares))
        # Compute partial decryptions from each key share
        # Each returns a list of PartialDecryption objects, one per bit
        partial_from_share0 = self.partial_decrypt(encrypted_msg, key_shares[0])
        partial_from_share1 = self.partial_decrypt(encrypted_msg, key_shares[1])
        
        # Combine: interleave them so we have [share0_bit0, share0_bit1, ..., share1_bit0, share1_bit1, ...]
        partial_combined = partial_from_share0 + partial_from_share1
        
        print(f"Computed partial decryptions from {len(key_shares)} key shares")
        print(f"Total partial decryptions: {len(partial_combined)}")

        decrypted_msg = self._eval_threshold_decrypt(partial_combined, encrypted_msg)
        print(f"Final decrypted message: {decrypted_msg}")

        assert decrypted_msg == m, f"Expected {m}, got {decrypted_msg}"

    def test_threshold_elgamal_point(self):
        pub_key, key_shares, thresh_params = self.keygen_threshold()
        # print("Generated 2-of-2 threshold keys")

        m = 12
        # print(f"Original message: {m}")

        encrypted_msg = self.enc(pub_key, m)
        # print(f"Encrypted message: {len(encrypted_msg)} ciphertexts (one per bit)")

        # Compute partial decryptions from each key share
        # Each returns a list of PartialDecryption objects, one per bit
        partial_from_share0 = self.partial_decrypt(encrypted_msg, key_shares[0])
        partial_from_share1 = self.partial_decrypt(encrypted_msg, key_shares[1])

        # encrypted_msg is:
        print(f"Encrypted message points: {encrypted_msg}")
        
        # Combine: interleave them so we have [share0_bit0, share0_bit1, ..., share1_bit0, share1_bit1, ...]
        partial_combined = partial_from_share0 + partial_from_share1
        
        print(f"Computed partial decryptions from {len(key_shares)} key shares")
        print(f"Total partial decryptions: {len(partial_combined)}")

        decrypted_msg = self.threshold_decrypt(partial_combined, encrypted_msg, thresh_params)
        # decrypted_msg = self.threshold_decrypt([partial_from_share0, partial_from_share0], encrypted_msg, thresh_params)
        print(f"Final decrypted message: {decrypted_msg}")

        msg_point = m * self.pp[1]
        
        assert decrypted_msg == msg_point, f"Expected {msg_point}, got {decrypted_msg}"
        print("Threshold ElGamal point decryption verified.")
       

    def test_threshold_elgamal_deterministic_0(self):
            
        pub_key, key_shares, thresh_params = self.keygen_threshold()
        # print("Generated 2-of-2 threshold keys")

        m = 0
        # print(f"Original message: {m}")

        encrypted_msg = self.enc(pub_key, m, r=1)
        # print(f"Encrypted message: {len(encrypted_msg)} ciphertexts (one per bit)")
        deterministic_encryption_of_0 = self.enc(pub_key, 0, r=1)
        encrypted_of_0 = self.enc(pub_key, 0)
        
        assert deterministic_encryption_of_0 != encrypted_of_0, f"Something is wrong with deterministic encryption of 0"
        assert encrypted_msg == deterministic_encryption_of_0, f"Deterministic encryption of 0 failed"
        print("Deterministic encryption of 0 verified.")

        # Compute partial decryptions from each key share
        # Each returns a list of PartialDecryption objects, one per bit
        partial_from_share0 = self.partial_decrypt(encrypted_msg, key_shares[0])
        partial_from_share1 = self.partial_decrypt(encrypted_msg, key_shares[1])

        # encrypted_msg is:
        print(f"Encrypted message points: {encrypted_msg}")
        
        # Combine: interleave them so we have [share0_bit0, share0_bit1, ..., share1_bit0, share1_bit1, ...]
        partial_combined = partial_from_share0 + partial_from_share1
        
        print(f"Computed partial decryptions from {len(key_shares)} key shares")
        print(f"Total partial decryptions: {len(partial_combined)}")

        decrypted_msg = self.threshold_decrypt(partial_combined, encrypted_msg, thresh_params)
        print(f"Final decrypted message: {decrypted_msg}")
        msg_point = m * self.pp[1]


        # Compare point coordinates
        assert decrypted_msg == msg_point, f"Expected {msg_point}, got {decrypted_msg}"

if __name__ == "__main__":
    el = ElGamal()
    # el.test_keygen()
    # el.test_int_to_bytes_enc()
    # el.test_elgamal()
    el.test_threshold_elgamal()
    el.test_threshold_elgamal_sub()
    # el.test_threshold_elgamal_on_target_reduction()
    # el.test_threshold_elgamal_on_target_reduction_eval()
    # el.test_eval_threshold_elgamal()
    # el.test_threshold_elgamal_point()
    # el.test_threshold_elgamal_deterministic_0()