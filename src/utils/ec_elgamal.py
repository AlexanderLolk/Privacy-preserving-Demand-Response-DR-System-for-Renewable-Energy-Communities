import threshold_crypto as tc
from Crypto.PublicKey import ECC

class ElGamal:
    """
    ElGamal implementation using Elliptic Curve Cryptography (ECC).
    Supports standard encryption/decryption, bitwise encryption for integers, 
    and threshold decryption using Shamir's Secret Sharing.

    References:
        - code used for threshold decryption: https://github.com/hyperion-voting/hyperion/blob/main/primitives.py#L227, https://github.com/tompetersen/threshold-crypto
    """
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
        Generates a public/private key pair for ElGamal encryption.
        
        The private key (dk) is a random integer 'x'.
        The public key (ek) is the point X = x * G.

        Returns:
            tuple: ((public_key, public_parameters), private_key)
        """
        if pp is not None:
            self.pp = pp

        x = tc.number.random_in_range(2, self.pp[2])
        ek = x * self.pp[1]
        dk = x
        return ((ek, self.pp), dk) 

    def __int_to_bits(self, message: int):
        """
        Helper function to convert an integer into a list of bits.
        
        Args:
            message (int): The integer message to convert.

        Returns:
            list: A list of integers (0 or 1) representing the message binary.
                  The order is from Most Significant Bit (MSB) to Least Significant Bit (LSB).
        """
        if message == 0:
            return [0]

        length = message.bit_length()
        
        list_bits = []

        # Extracts the bit at position i
        # Example: n = 13 (1101) & i = 2
        # (13 >> 2) = (1101) >> 2 = 3 (0011)
        # 3 (0011) & 1 (0001) = 1 (0001)
        for i in reversed(range(length)):
            list_bits.append(((message >> i) & 1))

        return list_bits
    
    def __bits_to_int(self, bits: list):
        """
        Helper function to reconstruct an integer from a list of bits.

        Args:
            bits (list): A list of integers (0 or 1).

        Returns:
            int: The reconstructed integer value.
        """
        message = 0
        
        for bit in bits:
            # Append one bit to the right side of the number
            # example: wants to add 0101 into message
            #   message = (message << 1) | 1   # 0000 -> 0001 (1)
            #   message = (message << 1) | 0   # 0001 -> 0010 (2)
            #   message = (message << 1) | 1   # 0010 -> 0101 (5)
            #   result: 5 (0101)
            message = (message << 1) | bit

        return message


    def encrypt_single(self, encryption_key: ECC.EccPoint, message: int):
        """
        Encrypts a single message using standard EC-ElGamal.

        Args:
            encryption_key (ECC.EccPoint): The recipient's public key.
            message (int): The message to encrypt. If int, it is mapped to a point (message * G).

        Returns:
            tuple: (C1, C2) representing the ciphertext points.
        """
        
        r = tc.number.random_in_range(2, self.pp[2])
    
        if isinstance(message, int):
            message = message * self.pp[1]


        c1 = r * self.pp[1]
        c2 = (r * encryption_key) + message
        
        return (c1, c2)
    
    def enc(self, encryption_key: ECC.EccPoint, message: int, r=None):
        """
        Performs bitwise encryption of an integer message.
        
        Decomposes the integer into bits, maps each bit to a point (0*G or 1*G),
        and encrypts each bit individually.

        Args:
            encryption_key (ECC.EccPoint): The recipient's public key.
            message (int): The integer message to encrypt.
            r (int, optional): A specific random scalar to use. If None, one is generated.

        Returns:
            list: A list of (C1, C2) tuples, one for each bit of the message.
        """
        
        if r is None:
            r = tc.number.random_in_range(2, self.pp[2])
        
        list_bits = self.__int_to_bits(message)
        encryptions = []
        for bit in list_bits:
            bit_point = bit * self.pp[1]
            c1 = r * self.pp[1]
            c2 = (r * encryption_key) + bit_point
            encryptions.append((c1, c2))

        return encryptions
    
    def __check_if_zero_or_one(self, message_points: list):
        """
        Maps decrypted EC points back to bits (0 or 1).
        
        It checks if the point matches 1*G. If yes, bit is 1. Otherwise, assumes 0 (Identity point).

        Args:
            message_points (list): A list of EC Points.

        Returns:
            list: A list of integers (0 or 1).
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
        Decrypts a single ciphertext tuple (C1, C2).
        
        Standard decryption:
        S = Private_Key * C1
        Message_Point = C2 - S

        Args:
            secret_key (int): The private key.
            ciphertext (tuple): The (C1, C2) tuple.

        Returns:
            EccPoint: A ecc point.
        """
        c1 = ciphertext[0]
        c2 = ciphertext[1]
        c1_com = (self.pp[2] + -secret_key) * c1
        s2 = c2 + c1_com
        return s2
    
    def dec(self, secret_key, ciphertexts):
        """
        Decrypts a list of bit-ciphertexts and reconstructs the original integer.
        
        Args:
            secret_key (int): The private key.
            ciphertexts (list): A list of (C1, C2) tuples (one per bit).

        Returns:
            int: The reconstructed integer message.
        """
        point_messages = []
        for ciphertext in ciphertexts:
            c1 = ciphertext[0]
            c2 = ciphertext[1]
            
            mol_inv = self.pp[2] + -secret_key
            s = mol_inv * c1
            message_point = c2 + s
            
            point_messages.append(message_point)
        list_bits = self.__check_if_zero_or_one(point_messages)
        return self.__bits_to_int(list_bits)
        
    # threshold partial decryption
    def keygen_threshold(self, pp=None):
        """
        Generates a public key and secret key shares for Threshold ElGamal.
        
        Uses Shamir's Secret Sharing (via the external library threshold crypto (tc)) to split 
        the private key into multiple shares.

        Args:
            pp: Public parameters (curve, generator, order).

        Returns:
            tuple: (Public_Key, Key_Shares, Threshold_Params)
        """
        
        thresh_params = tc.ThresholdParameters(2, 2)
        encryption_key, key_shares = tc.create_public_key_and_shares_centralized(self.pp[0], thresh_params)
        
        self.thresh_params = thresh_params
        
        # encryption_key.Q = ek
        return encryption_key.Q, key_shares, thresh_params
    
    def partial_decrypt(self, ciphertexts, key_share: tc.KeyShare):
        """
        Computes a partial decryption for a list of ciphertexts using a single key share.
        
        For each ciphertext (C1, C2), it computes share_i = x_i * C1.
        
        Args:
            ciphertexts (list): List of (C1, C2) tuples.
            key_share (tc.KeyShare): The secret share belonging to a specific party.

        Returns:
            list: A list of PartialDecryption objects containing the share index and the computed point.
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
        Combines multiple partial decryptions to obtain the original integer message.
        
        This function performs Lagrange Interpolation to reconstruct the shared secret's 
        effect (x * C1) from the partial shares and subtracts it from C2 to recover the message.
        
        The partial_decryptions list is expected to be flat and ordered by share, 
        containing all bit-shares for Share_0, then all bit-shares for Share_1, etc.

        Args:
            partial_decryptions (list): Flat list of PartialDecryption objects from all participants.
            encrypted_message (list): List of (C1, C2) tuples representing the encrypted bits.
            threshold_params (tc.ThresholdParameters): Parameters used for the secret sharing scheme.

        Returns:
            ECC.EccPoint: The reconstructed message as a point on the curve (Message_Value * g).
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
                bit_partials.append(pd)
            
            # [share0_bit0, share1_bit0]
            partial_by_bit.append(bit_partials)
        
        # Decrypt each bit position
        decrypted_bits = []
        for i, bit_partials in enumerate(partial_by_bit):
            c1, c2 = encrypted_message[i]
            
            partial_indices = [dec.x for dec in bit_partials]
            
            # Lagrange coefficients are used to combine the partial decryptions from key shares to
            # reconstruct the decryption key (or its effect) and thus recover the original message.
            lagrange_coefficients = [
                tc.lagrange_coefficient_for_key_share_indices(
                    partial_indices, idx, self.curve
                )
                for idx in partial_indices
            ]
            
            summands = [
                (lagrange_coefficients[i].coefficient * bit_partials[i].yC1)
                for i in range(0, len(bit_partials))
            ]
            
            # homomorphic property
            accumulated_point = tc.number.ecc_sum(summands)
            
            # Recover the message point: M = C2 - (nonce * decryption key * g) where (...) is the sum in accumulated_point
            restored_point = c2 + (-accumulated_point)
            
            bit = self.__check_if_zero_or_one([restored_point])[0]
            
            decrypted_bits.append(bit)
        
        # Convert bits back to integer
        decrypted_message = self.__bits_to_int(decrypted_bits)

        # Convert int to point
        decrypted_message_point = decrypted_message * self.pp[1] 

        return decrypted_message_point
    
    def _eval_threshold_decrypt(
        self,
        partial_decryptions: list,
        encrypted_message: list,
    ):
        """
        An Eval variant of threshold decryption that returns the integer value directly.
        
        Identical logic to threshold_decrypt but returns the raw integer instead of the 
        point on the curve. Used primarily for Eval where Eval expects an int.

        Args:
            partial_decryptions (list): Flat list of PartialDecryption objects.
            encrypted_message (list): List of (C1, C2) tuples.

        Returns:
            int: The decrypted integer message.
        """
        
        num_bits = len(encrypted_message)
        num_shares = len(partial_decryptions) // num_bits
        
        partial_by_bit = []
        for i in range(num_bits):
            bit_partials = []
            for share_i in range(num_shares):
                pd = partial_decryptions[share_i * num_bits + i]
                bit_partials.append(pd)
            
            partial_by_bit.append(bit_partials)
        
        decrypted_bits = []
        for i, bit_partials in enumerate(partial_by_bit):
            c1, c2 = encrypted_message[i]
            
            partial_indices = [dec.x for dec in bit_partials]

            lagrange_coefficients = [
                tc.lagrange_coefficient_for_key_share_indices(
                    partial_indices, idx, self.curve
                )
                for idx in partial_indices
            ]
            
            summands = [
                (lagrange_coefficients[i].coefficient * bit_partials[i].yC1)
                for i in range(0, len(bit_partials))
            ]
            
            accumulated_point = tc.number.ecc_sum(summands)
            
            restored_point = c2 + (-accumulated_point)
            
            bit = self.__check_if_zero_or_one([restored_point])[0]
            decrypted_bits.append(bit)
        
        decrypted_message = self.__bits_to_int(decrypted_bits)

        return decrypted_message
