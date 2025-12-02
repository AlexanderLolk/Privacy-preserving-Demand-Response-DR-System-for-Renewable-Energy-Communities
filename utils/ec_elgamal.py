import threshold_crypto as tc
from Crypto.PublicKey import ECC

# params for threshold_crypto
# G                 = ECC._curves[curve_name]
# g                 = curve_params.P 
# order             = curve_params.order
# order.random()    = number.random_in_range(1, curve_params.order) AKA d
# pk                = Q
# sk                = d

class ElGamal:

    def __init__(self, curve_name="P-256"):
        self.curve = tc.CurveParameters(curve_name)
        
    def keygen(self):
        """
        """
        x = tc.number.random_in_range(2, self.curve.order)
        return x, x * self.curve.P

    def encrypt(self, public_key, message):
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
        # return [r * self.curve.P, (r * public_key.Q) + (message), r,]
        return [c1, c2]
    
    def really_decrypt_message_for_real(self, message_point):
        """
        """
        for i in range(1000):
            if (i * self.curve.P) == message_point:
                return i
            
    def decrypt(self, secret_key, ciphertext):
        """
        """
        c1 = ciphertext[0]
        c2 = ciphertext[1]
        s = (self.curve.order + -secret_key) * c1
        return self.really_decrypt_message_for_real(c2 + s)
           
    # threshold partial decryption
    def keygen_threshold(self, threshold=True, t=2, n=2):
        """
        """
        if threshold:
            thresh_params = tc.ThresholdParameters(t, n)
            public_key, key_shares = tc.create_public_key_and_shares_centralized(self.curve, thresh_params)
            return public_key, key_shares
    
    def partial_threshold_decrypt(self, encrypted_message, key_share):
        encrypted_message = tc.EncryptedMessage(encrypted_message[0], encrypted_message[0], bytes(1))
        return tc.compute_partial_decryption(encrypted_message, key_share)

    def decrypt_threshold(self, partial_decryptions, encrypted_message, thres_params):
        return tc.decrypt_message(partial_decryptions, encrypted_message, thres_params)
    
    def partial_decrypt(self, ciphertext, key_share: tc.KeyShare):
        # c0 = ciphertext[0]
        # v_y = c0 * key_share.y
        # v_y = ciphertext * key_share.y
        # return tc.PartialDecryption(key_share.x, v_y, self.curve)
        c0 = ciphertext[0]
        v_y = c0 * key_share.y
        return tc.PartialDecryption(key_share.x, v_y, self.curve)
    
    def threshold_decrypt(
        self,
        partial_decryptions: list,
        encrypted_message: list,
        threshold_params: tc.ThresholdParameters,
    ):
        """Combines multiple partial decryptions to obtain the original message"""
        
        partial_indices = [dec.x for dec in partial_decryptions]
        lagrange_coefficients = [
            tc.lagrange_coefficient_for_key_share_indices(
                partial_indices, idx, self.curve
            )
            for idx in partial_indices
        ]

        summands = [
            lagrange_coefficients[i].coefficient * partial_decryptions[i].yC1
            for i in range(0, len(partial_decryptions))
        ]
        restored_kdP = tc.number.ecc_sum(summands)

        c2 = encrypted_message[1]  # Extract C2 from ciphertext
        restored_point = c2 + (-restored_kdP)

        # Convert point back to integer
        return self.really_decrypt_message_for_real(restored_point)

    def test_hyp_elgamal(self):
        sk, pk = self.keygen()
        print("sk is: " + str(sk))
        print("pk is: " + str(pk))
        
        m = 123
        print("Original message (integer): " + str(m))
        
        cipher = self.encrypt(pk, m)
        print("Encrypted message: " + str(cipher))
    
        message_dec_int = self.decrypt(sk, cipher)
        print("Decrypted message (integer): " + str(message_dec_int))
        
        assert m == message_dec_int, f"Expected {m}, got {message_dec_int}"

    def test_threshold_elgamal(self):
            
        pub_key, key_shares = self.keygen_threshold(threshold=True, t=2, n=2)
        print("Generated 2-of-2 threshold keys")

        m = 123
        print(f"Original message: {m}")

        encrypted_msg = self.encrypt(pub_key, m)
        print("Encrypted message: " + str(encrypted_msg))

        partial_decs = [
            self.partial_decrypt(encrypted_msg, key_shares[0]),
            self.partial_decrypt(encrypted_msg, key_shares[1])
        ]
        print("Computed 2 partial decryptions")

        thresh_params = tc.ThresholdParameters(2, 2)
        # decrypted_msg = self.decrypt_threshold(partial_decs, encrypted_msg, thresh_params)
        decrypted_msg = self.threshold_decrypt(partial_decs, encrypted_msg, thresh_params)
        print(f"Decrypted message: {decrypted_msg}")

        # assert str(m) == decrypted_msg, "Decryption failed"
        assert m == decrypted_msg, f"Decryption failed: expected {m}, got {decrypted_msg}"
        
el = ElGamal()
el.test_hyp_elgamal()
el.test_threshold_elgamal()