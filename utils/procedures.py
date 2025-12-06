import random
import utils.signature as sig
import utils.NIZKP as nizkp
from utils.ec_elgamal import ElGamal
from utils.dec_proof import prove_correct_decryption
import threshold_crypto as tc

class Procedures:
    
    def __init__(self, curve="P-256"):
        self.pp = self.pub_param(curve)
        self.ahe = ElGamal(self.pp)
        
    def pub_param(self, curve="P-256"):
        curve = tc.CurveParameters(curve)
        g = curve.P
        order = curve.order
        return (curve, g, order)
    
    # SKey_Gen(id, pp) → ((id, pk), sk)
    # SKeyGen(id, pp) to generate a signing key pair ((id, pk), sk) and publishes (id, pk) 
    # generates signature key pair (sk, pk) for identity id
    def skey_gen(self, id=random, pp=None):
        """Generate a signing keypair and a Schnorr NIZKP for the public key.

        Args:
            id: identifier for the key owner (may be a random generator by default).
            pp: public parameters tuple as returned by `pub_param`.

        Returns:
            tuple[str, tuple[EcPt, tuple[EcGroup, EcPt, Bn], tuple[Bn, Bn, EcPt]], Bn]: 
                ((id, (pk, pp, proof)), sk)
                where `pk` is the public signing key, `proof` is a Schnorr NIZKP,
                and `sk` is the signing secret key.
        """
        if pp is None:
            pp = self.pp
            

        sk, pk = sig.key_gen("P-256")
        assert pk == sk * pp[1], "Public key does not match private key"

        proof =  nizkp.schnorr_NIZKP_proof(pk, pp, sk)
        return ((id, (pk, pp, proof)), sk)

    # EKeyGen(pp) → (ek, dk): On input of the public parameter pp, executes (ek, dk) ← AHE.KeyGen(1λ)
    # which outputs encryption key pair.
    # It then computes πdk ← Proofdk((pp, ek), dk), updates ek such
    # that ek contains pp along with πdk, and returns (ek, dk).
    def ekey_gen(self, pp=None):
        """Generate an ElGamal encryption keypair and a sample decryption proof.

        This function also computes a short non-interactive proof for a sample
        message to allow verifiers to check that the secret key can decrypt
        correctly.

        Args:
            pp (tuple[EcGroup, EcPt, Bn]): 

        Returns:
            tuple[tuple[EcPt, tuple[EcGroup, EcPt, Bn], tuple[EcPt, tuple[EcPt, EcPt], tuple[EcPt, EcPt], Bn]], Bn]: 
            where `ek` is the public encryption key,
            πdk` is the produced proof, and `dk` is the secret key.
        """
        if pp is None:  
            pp = self.pp

        ek, dk_key_share, thres_param = self.ahe.keygen_threshold(pp)

        # generate_message = 42
        # (C1, C2) = elgamal_encrypt(pp, ek, M)
        # cts = ElGamal.enc(ek, generate_message)

        # Generate proof of correct decryption for threshold decryption
        # πdk = prove_correct_decryption(ek, pp, m_scalar, dk)
        return ((ek, thres_param, "place holder proof"), dk_key_share)

    def ekey_gen_single(self,pp=None):
        """Generate an ElGamal encryption keypair and a sample decryption proof.

        This function also computes a short non-interactive proof for a sample
        message to allow verifiers to check that the secret key can decrypt
        correctly.

        Args:
            pp (tuple[EcGroup, EcPt, Bn]): 

        Returns:
            tuple[tuple[EcPt, tuple[EcGroup, EcPt, Bn], tuple[EcPt, tuple[EcPt, EcPt], tuple[EcPt, EcPt], Bn]], Bn]: 
            where `ek` is the public encryption key,
            πdk` is the produced proof, and `dk` is the secret key.
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


    # mix shuffles a n anonymized list of pk_i
    # REPORT:
    # id_a_pk[] is a list of public keys
    # sends an anonymized list of public keys along with the proof of shuffle
    def mix_id(self, ID_pk):
        """Anonymise and shuffle a list of identity public keys.

        Args:
            ID_pk (list[tuple[EcPt, tuple[EcGroup, EcPt, Bn], tuple[Bn, Bn, EcPt]]]): tuple of tuples (id, (pk, pp, proof)).

        Returns:
            tuple[list[EcPt], 
                tuple[tuple[EcPt, EcPt, EcPt, EcPt, list[EcPt]], 
                    tuple[Bn, Bn, Bn, Bn, list[Bn], list[Bn]], 
                    list[EcPt],
                    list[EcPt],
                    EcPt,
                    list[EcPt]]]:
        """
        # ID_pk: list of tuples (id, (pk, pp, proof))
        from utils.shuffle import Shuffle
        shuffle = Shuffle(self.pp)
        
        if not ID_pk:
            return ([], {}, None)
        
        N = len(ID_pk)
        Id_A_pk = []
        for idpk in ID_pk:
            pk = idpk[1][0]
            Id_A_pk.append(pk)

        # TODO MAKE SURE IT RETURN G + R_PRIME INSTEAD OF JUST R_PRIME
        e_prime, r_prime, ψ = shuffle.GenShuffle(Id_A_pk) 
        
        # proof of shuffle and anonymised list of pks
        # TODO is pp[1] = pk?
        # TODO WHAT PK SOULD BE USED HERE?
        πmix_proof= shuffle.GenProof(Id_A_pk, e_prime, r_prime, ψ, pk=self.pp[1])

        return (e_prime, r_prime, πmix_proof)

    # Report(id, sk, ek, m, t) → (pk, (t, ct, σ))
    user_info = {}

    def report(self, id, sm_sk, dso_ek, m, t, sm_pk):
        """Create a report by encrypting a message and signing the tuple.

        The message `m` is converted to binary and each bit is encrypted with
        the provided ElGamal key. The resulting ciphertexts are then signed
        using the user's signing key.

        Args:
            id (str): reporter identifier.
            sk (Bn): reporter signing secret key.
            ek (EcPt): encryption keypair/parameters expected by `ahe.enc`.
            m (int): integer message to be encoded as binary bits.
            t (int): timestamp or round identifier included in the signed message.
            user_pk (EcPt): the reporter's public key tuple (pk, pp, proof)

        Returns:
            tuple[tuple[EcPt, tuple[EcGroup, EcPt, Bn], tuple[Bn, Bn, EcPt]], tuple[int, list[tuple[EcPt, EcPt]], tuple[Bn, Bn, EcPt]]]:
                (user_pk, (t, ct, signing_σ))
        """
        
        # encrypt
        # the message is already bits since enc took care of converting it to bits
        if m > 0:
            cts = self.ahe.enc(dso_ek[0], m)
        else:
            # deterministic encryption of 0
            cts = self.ahe.enc(dso_ek[0], m, 1)

        # ct = [self.ahe.enc(ek[0], ek[1], m) for m in mbin]

        # sign (pk = (pk, pp, proof))
        msg = str((t, cts))
        signing_σ = sig.schnorr_sign(sm_sk, dso_ek[1], msg)

        return (sm_pk, (t, cts, signing_σ))
    
    # def consumption_report(self, dso_ek, sm_sk, m: int, t, sm_pk):
    #     """Create a consumption report by encrypting a message.

    #     The message `m` is converted to binary and each bit is encrypted with
    #     the provided ElGamal key.

    #     Args:
    #         m (int): integer message to be encoded as binary bits.

    #     Returns:
    #         list[tuple[EcPt, EcPt]]: list of ciphertexts.
    #     """
 
    #     cts = self.ahe.enc(dso_ek[0], m)
    #     msg = str((t, cts))
    #     signing_σ = sig.schnorr_sign(sm_sk, dso_ek[1], msg)
        
    #     return (sm_pk(cts, signing_σ)
