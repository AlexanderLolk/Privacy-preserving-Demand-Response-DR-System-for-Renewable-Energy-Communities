import random
import time
from src.utils.signature import Signature
import src.utils.private_key_proof as nizkp
from src.utils.ec_elgamal import ElGamal
from src.utils.elgamal_dec_proof import prove_correct_decryption, prove_partial_decryption_share
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
        self.r = tc.random_in_range(2, self.pp[2]-1)
        
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

        self.sig = Signature()
        sk, pk = self.sig.key_gen("P-256")
        assert pk == sk * pp[1], "Public key does not match private key"
        
        # self.

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
        Generates a standard ElGamal encryption keypair and a decryption proof.

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

    def log_phase(self, name, start_time):
        duration = time.time() - start_time
        print(f"[PERFORMANCE] {name} completed in {duration:.4f} seconds")


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

        start_time = time.time()
        # set up the shuffle proof
        e_prime, r_prime, ψ = shuffle.GenShuffle(Id_A_pk)
        self.log_phase("GenShuffle", start_time) 
        start_time = time.time()
        # proof of shuffle and anonymised list of pks
        πmix_proof= shuffle.GenProof(Id_A_pk, e_prime, r_prime, ψ, expo)
        self.log_phase("GenProof", start_time) 

        return (e_prime, r_prime, πmix_proof)

    # Report(id, sk, ek, m, t) → (pk, (t, ct, σ))
    user_info = {}

    def report(self, id, sm_sk, dso_ek, m, t, sm_pk):
        """
        Creates a signed, encrypted report.

        The message m (int) is encrypted using bitwise ElGamal encryption under 
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
        r = tc.random_in_range(2, self.pp[2])
        if m > 0:
            cts = self.ahe.enc(dso_ek[0], m, self.r)
            # cts = self.ahe.enc(dso_ek[0], m)
        else:
            # deterministic encryption of 0
            cts = self.ahe.enc(dso_ek[0], m, 1)

        # sign (pk = (pk, pp, proof))
        msg = str((t, cts))
        signing_σ = self.sig.schnorr_sign(sm_sk, dso_ek[1], msg)

        return (sm_pk, (t, cts, signing_σ))
    
    def __export_bytes(self, x):
        """
        Helper function to serialize various object types into bytes for hashing.
        
        Args:
            x: The object to serialize (EcPoint, bytes, bytearray, or other types).

        Returns:
            bytes: The byte representation of the object.
        """
        if hasattr(x, "export"):
            return x.export()
        if isinstance(x, (bytes, bytearray)):
            return bytes(x)
        return str(x).encode()

    def anonym(self, inputs=None, r_prime_list=None, secret_key_T=None):
        """
        Aggregates user reports, derives anonymized public keys, and signs the batch for the bulletin board.

        Current Limitations:
        - It uses a placeholder string instead of a NIZKP instead of generating real Zero-Knowledge Proofs 
        linking the new `pk_prime` to the original `pk` and signature.
        - It assumes alignment between `inputs` and `r_prime_list`.
        - A CGate has not been implemented


        Args:
            inputs (list): List of smart meter reports. Each report is a tuple:
                        ( (pk, pp, proof), (t, cts, signature) )
            r_prime_list (list): List of blinding factors (points or scalars) used to re-randomize the public keys.
            secret_key_T (int): The private signing key of the entity (TTP/Aggregator) validating this batch.

        Returns:
            tuple: (Batch_Signature, Published_List)
                - Batch_Signature: (Hash_Integer, Schnorr_Signature)
                - Published_List: List of (pk_prime, cts, t, pi) tuples.
        """
        
        # print("[NOT IMP] in anonym.Anonym: compute zero-knowledge proof of knowledge signature σ_i on (pk_i, t, ct_i) and zero-knowledge proof of knowledge ")
    
        published = []
        for (sm_report, r_prime) in zip(inputs, r_prime_list):
            try:
                pk_tuple, body = sm_report
                pk, pp, s_proof = pk_tuple
                t, cts, signature = body
            except ValueError:
                raise ValueError("Invalid input format for sm_report")
            
            # TODO check if index is correct, normally it is done by ZKP
            # ANSWER: THEY DO NOT ALIGN!!!!!!
            # FOR NOW, AGG HAS A MAP TO STORE THE pk TO pk_prime
            # pk_prime = (r_prime) * pk_pt

            # Compute the re-randomized public key: pk' = pk + r'
            # Note: If r_prime is a blinding factor point (r*G), this is EC addition.
            pk_prime = r_prime + pk

            # placeholder proof
            pi = "NIZKP here"
            published.append((pk_prime, cts, t, pi))

        msg_bytes = b""

        for (pk_prime, ct, t, pi) in published:
            c1, c2 = ct[0]
            msg_bytes += self.__export_bytes(pk_prime)
            msg_bytes += self.__export_bytes(c1)
            msg_bytes += self.__export_bytes(c2)
            msg_bytes += self.__export_bytes(t)
            msg_bytes += self.__export_bytes(pi)
        
        # Use the first pk_prime as the 'randomness commitment' (R) for the Hash function
        # This binds the hash to the specific curve/batch context.
        commiment = published[0][0] # pk_prime (usage is to make sure it's deterministic)
        
        # hash it
        ht_bn = self.sig.Hash(commiment, msg_bytes, pp[2])

        # Sign the batch hash with the authority's secret key
        sign_it = self.sig.schnorr_sign(secret_key_T, pp, ht_bn)
        
        bb = (ht_bn, sign_it)
        pbb = published
        
        return bb, pbb