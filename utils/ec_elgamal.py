import threshold_crypto as tc
# from Crypto.PublicKey import ECC

# params for threshold_crypto
# G                 = ECC._curves[curve_name]
# g                 = curve_params.P 
# order             = curve_params.order
# order.random()    = number.random_in_range(1, curve_params.order) AKA d
# pk                = Q
# sk                = d

class ElGamal:

    # def __init__(self, curve_name="P-256"):
    #     self.curve = tc.CurveParameters(curve_name)
        
    def keygen(self, pp=None):
        """
        """
        if pp is None:
            self.curve = tc.CurveParameters("P-256")
            self.g = self.curve.P
            self.order = self.curve.order
        else:
            self.curve = pp
            self.g = pp.P
            self.order = pp.order
        
        x = tc.number.random_in_range(2, self.order)
        return ((self.curve, self.g, self.order, x * self.g) , x) 

    def _int_to_bits(self, message: int):
        length = message.bit_length()
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


    def encrypt_single(self, public_key, message: int):
        """
        """
        
        r = tc.number.random_in_range(2, self.curve.order)
        
        if isinstance(message, int):
            message = message * self.curve.P

        if hasattr(public_key, 'Q'):
            pk_point = public_key.Q
        else:
            pk_point = public_key

        c1 = r * self.curve.P
        c2 = (r * pk_point) + message
        
        return [c1, c2]
    
    def enc(self, encryption_key, message: int, r=None):
        """
        """
        if isinstance(encryption_key, tuple):
            _, _, _, encryption_key = encryption_key
        
        if r is None:
            r = tc.number.random_in_range(2, self.order)
        
        list_bits = self._int_to_bits(message)

        encryptions = []
        for bit in list_bits:
            bit_point = bit * self.g
            c1 = r * self.g
            c2 = (r * encryption_key) + bit_point
            encryptions.append((c1, c2))
            
        return encryptions
    
    def _check_if_zero_or_one(self, message_points: list):
        """
        """
        one_point = 1 * self.g
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
        s = (self.curve.order + -secret_key) * c1
        s2 = c2 + s
        return self._check_if_zero_or_one(c2 + s)
    
    def dec(self, secret_key, ciphertexts):
        """
        """
        point_messages = []
        for ciphertext in ciphertexts:
            c1 = ciphertext[0]
            c2 = ciphertext[1]
            mol_inv = self.curve.order + -secret_key
            s = mol_inv * c1
            message_point = c2 + s
            point_messages.append(message_point)
        list_bits = self._check_if_zero_or_one(point_messages)
        return self._bits_to_int(list_bits)
           
    # threshold partial decryption
    def keygen_threshold(self, pp=None):
        """
        """
    
        if pp is None:
            self.curve = tc.CurveParameters("P-256")
            self.g = self.curve.P
            self.order = self.curve.order
        else:
            self.curve = pp
            self.g = pp.P
            self.order = pp.order
        
        thresh_params = tc.ThresholdParameters(2, 2)
        public_key, key_shares = tc.create_public_key_and_shares_centralized(self.curve, thresh_params)
        
        self.thresh_params = thresh_params
        return public_key.Q, key_shares, thresh_params
    
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
        expected_value: int,
    ):
        """
            Combines multiple partial decryptions to obtain the original message.
            encrypted_message is a list of (c1, c2) tuples, one for each bit.
            partial_decryptions is a flat list of PartialDecryption objects from all key shares and all bits.
            We need to organize them: group by bit index first, then by key share.
        """
        
        num_bits = len(encrypted_message)
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
        
        # print(f"Decrypted message: {decrypted_message}, Expected: {expected_value}")

        return decrypted_message 


    ###
    # tests
    ###
    def test_int_to_bytes_enc(self):
        msg = 12732423
        # binary_string = f'{msg:b}'
        # print("msg to bits: " + binary_string)

        # self.int_to_bits(msg)
        ek, dk = self.keygen()
        encryptions = self.enc(ek, msg)
        # print(str(encryptions))
        message = self.dec(dk, encryptions)
        # print("decrypted message: " + str(message))
        # ek, dk = self.keygen()
        # cipher = self.encrypt(ek, msg)
        # message_dec_int = self.decrypt(dk, cipher, msg)
        # assert msg == message_dec_int
         

    def test_elgamal(self):
        ek, dk = self.keygen()
        print("sk is: " + str(dk))
        print("pk is: " + str(ek))
        
        m = 123
        print("Original message (integer): " + str(m))
        
        cipher = self.enc(ek, m)
        print("Encrypted message: " + str(cipher))
    
        message_dec_int = self.dec(dk, cipher)
        print("Decrypted message (integer): " + str(message_dec_int))
        
        assert message_dec_int == 123, f"expected 1, got {message_dec_int}"


    def test_threshold_elgamal(self):
            
        pub_key, key_shares, thresh_params = self.keygen_threshold()
        # print("Generated 2-of-2 threshold keys")

        m = 127
        # print(f"Original message: {m}")

        encrypted_msg = self.enc(pub_key, m)
        print(f"Encrypted message: {len(encrypted_msg)} ciphertexts (one per bit)")

        # Compute partial decryptions from each key share
        # Each returns a list of PartialDecryption objects, one per bit
        partial_from_share0 = self.partial_decrypt(encrypted_msg, key_shares[0])
        partial_from_share1 = self.partial_decrypt(encrypted_msg, key_shares[1])
        
        # Combine: interleave them so we have [share0_bit0, share0_bit1, ..., share1_bit0, share1_bit1, ...]
        partial_combined = partial_from_share0 + partial_from_share1
        
        print(f"Computed partial decryptions from {len(key_shares)} key shares")
        print(f"Total partial decryptions: {len(partial_combined)}")

        decrypted_msg = self.threshold_decrypt(partial_combined, encrypted_msg, thresh_params, m)
        print(f"Final decrypted message: {decrypted_msg}")

        assert decrypted_msg == m, f"Expected {m}, got {decrypted_msg}"
        
# el = ElGamal()
# # el.test_int_to_bytes_enc()
# # el.test_elgamal()
# el.test_threshold_elgamal()