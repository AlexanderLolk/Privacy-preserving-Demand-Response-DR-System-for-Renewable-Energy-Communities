import hashlib
from Crypto.PublicKey import ECC
import threshold_crypto as tc

class Signature:
    def key_gen(self, curve_name="P-256"):
        """
        Generates a standard Elliptic Curve key pair.

        Args:
            curve_name (str): The name of the curve to use (default "P-256").

        Returns:
            tuple: (private_key_integer, public_key_point)
        """
        key = ECC.generate(curve=curve_name)
        return key.d, key.public_key().pointQ

    def __point_to_bytes(self, point):
        """
        Serializes an Elliptic Curve point into bytes.
        
        Handles point objects from different libraries ('threshold_crypto' and 'Crypto.PublicKey.ECC').

        Args:
            point: The EC point object.

        Returns:
            bytes: The byte representation of the point (usually x-coord || y-coord).
        
        Raises:
            TypeError: If the point object type is not supported.
        """
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

    def Hash(self, R, msg, order):
        """
        Computes the challenge hash 'e' for the Schnorr signature.
        
        Implements: e = H(R || msg) mod q
        This binds the ephemeral commitment (R) and the message (msg) together.

        Args:
            R (Point): The ephemeral public key (randomness commitment).
            msg (int, bytes, Point, or str): The message being signed.
            order (int): The order of the elliptic curve group (q).

        Returns:
            int: The scalar challenge hash 'e'.
        """
        h = hashlib.sha256()
        
        # Hash the point R
        h.update(self.__point_to_bytes(R))

        # Convert msg to bytes based on its type
        if isinstance(msg, bytes):
            msg_bytes = msg
        elif isinstance(msg, int):
            msg_bytes = msg.to_bytes((msg.bit_length() + 7) // 8, 'big')
        elif hasattr(msg, 'x') and hasattr(msg, 'y'):
            msg_bytes = self.__point_to_bytes(msg)
        else:
            msg_bytes = str(msg).encode()

        h.update(msg_bytes)
        digest_bytes = h.digest()
        digest_int = int.from_bytes(digest_bytes, 'big')
        return digest_int % order

    def schnorr_sign(self, sk, pp, msg):
        """
        Generates a Schnorr signature for a message.
        
        Mathematical steps:
        1. Generate random nonce k.
        2. Compute commitment R = k * G.
        3. Compute challenge e = Hash(R, msg).
        4. Compute response s = k + (sk * e) mod order.
        
        Args:
            sk (int): The signer's private key (scalar).
            pp (tuple): Public parameters (curve, G, order).
            msg: The message to sign.

        Returns:
            tuple: (R, s) where R is the ephemeral point and s is the signature scalar.
        """
        g = pp[1]
        order = pp[2]
        
        k = tc.number.random_in_range(1, order)
        ephemeral_key = k * g
        challenge_hash = self.Hash(ephemeral_key, msg, order)

        signature = (int(k) + int(sk) * int(challenge_hash)) % int(order)
        return (ephemeral_key, signature)

    def schnorr_verify(self, pk, pp, msg, signature):
        """
        Verifies a Schnorr signature.
        
        Checks if: s * G == R + (e * PK)
        
        Derivation:
        s * G = (k + sk * e) * G
            = k * G + e * (sk * G)
            = R + e * PK

        Args:
            pk (Point): The signer's public key.
            pp (tuple): Public parameters (curve, G, order).
            msg: The message that was signed.
            signature (tuple): The signature (R, s).

        Returns:
            bool: True if the signature is valid, False otherwise.
        """
        g = pp[1]
        order = pp[2]
        R, s = signature
        
        e = self.Hash(R, msg, order)

        expected_point = int(s) * g
        reconstructed_point = R + int(e) * pk

        return expected_point == reconstructed_point

    #
    def schnorr_sign_list(self, sk, pp, msg_list):
        """
        Batch signs a list of messages.

        Args:
            sk (int): Private key.
            pp (tuple): Public parameters.
            msg_list (list): List of messages.

        Returns:
            list: A list of signature tuples [(R, s), ...].
        """
        signatures = []
        for msg in msg_list:
            sign = self.schnorr_sign(sk, pp, msg)
            signatures.append(sign)
        return signatures

    def schnorr_verify_list(self, pk, pp, msg_list, signatures):
        """
        Verifies a list of signatures against a list of messages.

        Args:
            pk (Point): Public key.
            pp (tuple): Public parameters.
            msg_list (list): List of messages.
            signatures (list): List of signature tuples corresponding to the messages.

        Returns:
            tuple: (all_valid, results)
                - all_valid (bool): True only if ALL signatures are valid.
                - results (list): List of tuples (index, message, is_valid) for detailed debugging.
        """
        results = []
        for i, (msg, signature) in enumerate(zip(msg_list, signatures)):
            is_valid = self.schnorr_verify(pk, pp, msg, signature)
            if not is_valid:
                results.append((i, msg, False))
            else:
                results.append((i, msg, True))
        
        all_valid = all(r[2] for r in results)
        return (all_valid, results)