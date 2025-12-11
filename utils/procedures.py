import random
import utils.signature as sig
import utils.schnorr_priv_key_proof as nizkp
from utils.ec_elgamal import ElGamal
from utils.elgamal_dec_proof import prove_correct_decryption, prove_partial_decryption_share
import threshold_crypto as tc

class Procedures:
    """
    High-level procedures for a privacy-preserving reporting system.
    Handles key generation, anonymous shuffling (Mix), and report creation/signing.
    """
    def __init__(self, curve="P-256"):
        """
        Initializes the Procedures instance.
        Sets up public parameters and the internal ElGamal instance.
        """
        self.pp = self.pub_param(curve)
        self.ahe = ElGamal(self.pp)
        
    def pub_param(self, curve="P-256"):
        """
        Loads and returns the public parameters for the specified elliptic curve.

        Args:
            curve (str): The name of the curve (default "P-256").

        Returns:
            tuple: (curve, g, order)
        """
        curve = tc.CurveParameters(curve)
        g = curve.P
        order = curve.order
        return (curve, g, order)
    
    # SKey_Gen(id, pp) → ((id, pk), sk)
    # SKeyGen(id, pp) to generate a signing key pair ((id, pk), sk) and publishes (id, pk) 
    # generates signature key pair (sk, pk) for identity id
    def skey_gen(self, id=random, pp=None):
        """
        Generates a signing keypair and a Schnorr Non-Interactive Zero-Knowledge Proof (NIZKP) 
        for the public key ownership.

        Args:
            id: The identity associated with this key.
            pp (tuple, optional): Public parameters. Uses self.pp if None.

        Returns:
            tuple: ((id, (pk, pp, proof)), sk)
        """
        if pp is None:
            pp = self.pp
            
        sk, pk = sig.key_gen("P-256")
        assert pk == sk * pp[1], "Public key does not match private key"

        proof =  nizkp.schnorr_NIZKP_proof(pk, pp, sk)
        return ((id, (pk, pp, proof)), sk)

    def ekey_gen(self, pp=None):
        """
        Generates a Threshold ElGamal encryption keypair and proves decryption capability.

        This function generates a shared public key and secret key shares. It then encrypts
        a sample message (42) and generates a Zero-Knowledge Proof (ZKP) that the key shares
        can correctly partially decrypt this test ciphertext.

        Args:
            pp (tuple, optional): Public parameters. Uses self.pp if None.

        Returns:
            tuple: ((pk, thres_param, (πdk0, πdk1)), dk_key_share)
        """
        if pp is None:  
            pp = self.pp

        ek, dk_key_share, thres_param = self.ahe.keygen_threshold(pp)

        generate_message = 42
        ct = self.ahe.encrypt_single(ek, generate_message)

        # Generate proof of correct decryption for threshold decryption
        πdk0 = prove_partial_decryption_share(pp, ct, dk_key_share[0])
        πdk1 = prove_partial_decryption_share(pp, ct, dk_key_share[1])
        
        return ((ek, thres_param, (πdk0, πdk1)), dk_key_share)

    def ekey_gen_single(self,pp=None):
        """
        Generates a standard (single-party) ElGamal encryption keypair and a decryption proof.

        This function creates a standard keypair, encrypts a sample message (200), and 
        generates a ZKP that the secret key can successfully decrypt this ciphertext.

        Args:
            pp (tuple, optional): Public parameters. Uses self.pp if None.

        Returns:
            tuple: ((Public_Key, Public_Params, Decryption_Proof), Secret_Key)
        """
        if pp is None:  
            pp = self.pp
            
        (ek, pp), dk = self.ahe.keygen(pp)

        generate_message = 200
        # (C1, C2) = elgamal_encrypt(pp, ek, M)
        cts = self.ahe.encrypt_single(ek, generate_message)

        # Generate proof of correct decryption for threshold decryption
        πdk = prove_correct_decryption(ek, pp, generate_message, dk, cts)
        
        return ((ek, pp, πdk), dk)

    def mix_id(self, ID_pk, expo):
        """
        Anonymizes and shuffles a list of identity public keys using shuffling.

        This function takes a list of public keys, creates permutations of them, re-randomizes them,
        shuffles their order, and generates a proof of correct shuffling. This breaks the link
        between the input order and output order, providing anonymity.

        Args:
            ID_pk (list): A list of tuples, where each item is (id, (pk, pp, proof)).
            pk (ECC.Point): The public key used for the shuffle encryption/re-encryption.

        Returns:
            tuple: (Shuffled_PKs, Randomness_Used, Shuffle_Proof)
        """

        from utils.shuffle import Shuffle
        shuffle = Shuffle(self.pp)
        
        if not ID_pk:
            return ([], {}, None)
        
        N = len(ID_pk)
        Id_A_pk = []
        for idpk in ID_pk:
            pk = idpk[1][0]
            Id_A_pk.append(pk)

        # set up the shuffle proof
        e_prime, r_prime, ψ = shuffle.GenShuffle(Id_A_pk) 
        
        # proof of shuffle and anonymised list of pks
        πmix_proof= shuffle.GenProof(Id_A_pk, e_prime, r_prime, ψ, expo)

        return (e_prime, r_prime, πmix_proof)

    # Report(id, sk, ek, m, t) → (pk, (t, ct, σ))
    user_info = {}

    def report(self, id, sm_sk, dso_ek, m, t, sm_pk):
        """
        Creates a signed, encrypted report.

        The message `m` (integer) is encrypted using bitwise ElGamal encryption under 
        the DSO's (Data Service Operator) encryption key. The time `t` and the ciphertexts 
        are then signed using the Smart Meter's (sm) secret signing key.

        Args:
            id: The identity of the reporter.
            sm_sk (int): Smart Meter's secret signing key.
            dso_ek (tuple): DSO's encryption key tuple containing (Public_Key, ...).
            m (int): The measurement/message to report.
            t (int): Timestamp or time epoch.
            sm_pk: Smart Meter's public key.

        Returns:
            tuple: (SmartMeter_PK, (Time, Ciphertexts, Signature))
        """
        if m > 0:
            cts = self.ahe.enc(dso_ek[0], m)
        else:
            # deterministic encryption of 0
            cts = self.ahe.enc(dso_ek[0], m, 1)

        # sign (pk = (pk, pp, proof))
        msg = str((t, cts))
        signing_σ = sig.schnorr_sign(sm_sk, dso_ek[1], msg)

        return (sm_pk, (t, cts, signing_σ))