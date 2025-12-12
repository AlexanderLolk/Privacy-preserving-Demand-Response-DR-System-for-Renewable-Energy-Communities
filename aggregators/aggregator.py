from utils.elgamal_dec_proof import verify_correct_decryption, prove_partial_decryption_share
from utils.procedures import Procedures

class Aggregator:
    """ 
    Represents the Energy Aggregator.
    
    The Aggregator acts as an intermediary between Smart Meters and the DSO/Board.
    Its responsibilities include:
     - Mixing (Anonymizing): Shuffling and re-randomizing Smart Meter public keys.
     - Collection: Receiving encrypted reports from Smart Meters.
     - Anonymization: Stripping any un-needed identifier data before going on the Board.
     - Partial Decryption: Using its secret key share to partially decrypt the final results.
    """
    def __init__(self, init_id="agg_id", pp=None):
        """
        Initializes the Aggregator.
        Generates signing keys and encryption keys (though encryption keys are often 
        just shares distributed by the DSO in this threshold scheme).
        """
        self.pro = Procedures()
        if pp is None:
           pp = self.pro.pub_param()

        ((self.id, (self.pk, self.pp, self.s_proof)), self.sk) = self.pro.skey_gen(init_id, pp)
        # primarily uses the key share 'dk' from the DSO.
        ((self.ek, _, self.e_proof), self.dk) = self.pro.ekey_gen_single(pp)

        self.participants = []
        self.participants_baseline_report = []
        self.participants_consumption_report = []
        self.pk_to_pk_prime = {}
        self.sm_ek = {}
    
    def get_id(self):
        """Returns the Aggregator's ID string."""
        return self.id

    def get_public_key(self):
        """Returns the Aggregator's signing public key package."""
        return (self.pk, self.pp, self.s_proof)
    
    def get_encryption_key(self):
        """Returns the Aggregator's own encryption key package."""
        return (self.ek, self.pp, self.e_proof)
    
    def get_agg_id_And_encryption_key(self):
        """Returns ID and Encryption Key."""
        message_to_verify = self.id + str(self.ek.x) + str(self.ek.y)
        return (self.id, self.get_encryption_key(), self.pro.sig.schnorr_sign(self.sk, self.pp, message_to_verify))

    def set_dso_public_keys(self, dso_pk, dso_ek):
        """
        Stores the DSO's public keys. 
        Needed to verify DSO signatures or encrypt data for the DSO.
        """
        self.dso_pk = dso_pk
        self.dso_ek = dso_ek
        
    def set_dso_dk(self, key_share):
        """
        Stores the Threshold Decryption Key Share assigned by the DSO.
        This share is used to partially decrypt the aggregated results.
        
        Args:
          key_share: The secret scalar share x_i.
        """
        from threshold_crypto import KeyShare
        x, enc_share, signature = key_share
        
        y = self.pro.ahe.dec(self.dk, enc_share)
        if self.pro.sig.schnorr_verify(self.dso_pk[0], self.dso_pk[1], str((x, y)), signature) == False:
            raise ValueError("DSO signature verification on dk share failed")

        key_share = KeyShare(x, y, self.pp[0])
        print(f"key_share set in agg: {key_share}")

        self.dk_share = key_share


    def set_sm_encrypytion_keys(self, sm, bb_Sm_registry=None):
        """
        Stores the Aggregator's encryption key.

        Args:
            agg_id (str): The Aggregator's identifier.
            agg_ek (tuple): The Aggregator's ElGamal encryption key structure.
        """
        id, (ek, pp, proof), signature = sm
        message_to_verify = id + str(ek.x) + str(ek.y)

        pk = None
        if bb_Sm_registry is not None:
            pk, _, _ = bb_Sm_registry


        if pk is None or pp is None:
            raise ValueError("pk could not be found in registy")
        if not self.pro.sig.schnorr_verify(pk, pp, message_to_verify, signature):
            raise ValueError("dso failed to verify aggregator")
        if not verify_correct_decryption(ek, pp, proof):
            raise ValueError("dso failed to verify aggregator's proof of correct decryption")

        self.sm_ek[id] = ek

    def create_mixed_anon_pk_set(self, ID_pk):
        """
        Executes the Mix shuffle protocol.
        
        Takes a list of real identities (Public Keys), shuffles them, and re-randomizes them.
        Generates a Zero-Knowledge Proof (πmix) that the output set is a valid shuffle of the input.

        Args:
          ID_pk: List of registered Smart Meter public keys.
        """
        self.mix_anon_list = self.pro.mix_id(ID_pk, self.pp[1])   

    def publish_mixed_keys(self):
        """ 
        Returns the result of the mixing process to be published on the Board.

        Returns:
            tuple: (List_of_Anonymized_PKs, Shuffle_Proof)
        """
        return (self.mix_anon_list[0], self.mix_anon_list[2])
    
    def set_anon_key_mix(self, sm, id):
        """
        Retrieves the specific blinding factor (randomness) used for a specific Smart Meter.
        
        This allows the Aggregator to privately inform the Smart Meter that they can recognice
        themselves in the anonymized list (since the random value is added to their key).
        
        Args:
          sm: Tuple containing the Smart Meter's ID and Public Key.

        Returns:
            tuple: (Blinding_Factor_Point, Signature)
        """
        if isinstance(sm, tuple):
            sm_pk = sm[0]
        else:
            sm_pk = sm

        _, g, _ = self.pp

        # using additive logic (pk + r*G)
        for r_prime in self.mix_anon_list[1]:

            # calculate r_prime * g
            blinding_factor = int(r_prime) * g

            # then add r_prime to public key
            pk_prime_check = sm_pk + blinding_factor
            
            for pk_prime in self.mix_anon_list[0]:
                if pk_prime_check == pk_prime:
                    sign_r_prime = self.pro.sig.schnorr_sign(self.sk, self.pp, str(r_prime))

                    # Store mapping of pk -> Blinding_Factor for later use in Anonym()
                    pk_str = str((sm_pk.x, sm_pk.y))
                    self.pk_to_pk_prime[pk_str] = blinding_factor
                    
                    enc_r_prime = self.pro.ahe.enc(self.sm_ek[id], r_prime)
                    
                    # return (blinding_factor, sign_r_prime)
                    return (enc_r_prime, sign_r_prime)
        
        print("Public key not found in r_prime")
        return None

    def check_sm_baseline(self, baseline_report, sm_id="NOT_SAID"):
        """
        Receives, verifies, and stores a report from a Smart Meter.
        
        It checks:
        1. The signature on the report.
        2. Whether the report is an "empty" zero-report (using the deterministic encryption check).
           - If it's a zero baseline report, the user is ignored (did not participate).
           - If it's a valid report, they are added to the participants list.

        Args:
          sm_report: The report tuple (PK, (Time, Ciphertext, Signature)).
          sm_id: ID for logging purposes.
          consumption (bool): False if this is a Baseline report, True if Consumption report.
        """
        (pk, (t, cts, signature)) = baseline_report
        
        sm_pk = pk[0]
        pp = pk[1]
        
        if not self.pro.sig.schnorr_verify(sm_pk, pp, str((t, cts)), signature):
            raise ValueError("baseline check failed")

        g = pp[1]

        # Generate a deterministic encryption of 0 to check against
        deterministic_check = self.pro.ahe.enc(self.dso_ek[0], 0, r=1)

        # Identify the anonymized key (pk') corresponding to this report
        pk_prime = None
        for r_prime in self.mix_anon_list[1]:
            blinding_factor = int(r_prime) * g
            pk_prime_check = sm_pk + blinding_factor
            
            for pk_prime_candidate in self.mix_anon_list[0]:
                if pk_prime_check == pk_prime_candidate:
                    pk_prime = pk_prime_check
        
        # If it's a baseline report and not zero (meaning sm wants to participate)
        if cts != deterministic_check:
            print(f"{sm_id} wants to join DR event \n")
            self.participants_baseline_report.append(baseline_report)
            self.participants.append(pk_prime)

    def check_sm_consumption(self, consumption_report, sm_id="NOT_SAID"):
        """
        Receives, verifies, and stores a report from a Smart Meter.
        
        It checks:
        1. The signature on the report.
        2. Whether the report is an "empty" zero-report (using the deterministic encryption check).
           - If it's a zero baseline report, the user is ignored (did not participate).
           - If it's a valid report, they are added to the participants list.

        Args:
          sm_report: The report tuple (PK, (Time, Ciphertext, Signature)).
          sm_id: ID for logging purposes.
          consumption (bool): False if this is a Baseline report, True if Consumption report.
        """
        (pk, (t, cts, signature)) = consumption_report
        
        sm_pk = pk[0]
        pp = pk[1]
        
        sm_consumption_verified = self.pro.sig.schnorr_verify(sm_pk, pp, str((t, cts)), signature)
        assert sm_consumption_verified, "Consumption signature verification failed"
        
        self.participants_consumption_report.append(consumption_report)
            
    def get_participants(self):
        """Returns list of anonymized public keys of participants."""
        return self.participants
    
    def get_participants_baseline(self):
        """Returns list of raw baseline reports."""
        return self.participants_baseline_report
    
    def get_participants_consumption(self):
        """Returns list of raw consumption reports."""
        return self.participants_consumption_report
    
    def make_anonym_baseline(self):
        """
        Executes the 'Anonym' protocol to publish reports to the Board.
        
        This batches the collected reports, replaces real PKs with Anonymized PKs,
        and signs the batch.

        Returns:
            tuple: (Batch_Signature, List_of_Anonymized_Entries)
        """
        # Match blinding factors to the sorted list of reports
        r_prime_list = []
        for (pk, _, _), _ in self.participants_baseline_report:
            pk_str = str((pk.x, pk.y))
            r_prime = self.pk_to_pk_prime[pk_str]
            r_prime_list.append(r_prime)
        return self.pro.anonym(self.get_participants_baseline(), r_prime_list, self.sk)
    
    def make_anonym_consumption(self):
        """
        Executes the 'Anonym' protocol to publish reports to the Board.
        
        This batches the collected reports, replaces real PKs with Anonymized PKs,
        and signs the batch.

        Returns:
            tuple: (Batch_Signature, List_of_Anonymized_Entries)
        """
        
        # Match blinding factors to the sorted list of reports
        r_prime_list = []
        for (pk, _, _), _ in self.participants_consumption_report:
            pk_str = str((pk.x, pk.y))
            r_prime = self.pk_to_pk_prime[pk_str]
            r_prime_list.append(r_prime)
        return self.pro.anonym(self.get_participants_consumption(), r_prime_list, self.sk)
    
    def partial_dec_reports(self, baseline_BB, consumption_PBB):
        """
        Performs partial decryption on reports gotten from the Bulletin Board.
        
        It iterates through the participants, finds their encrypted reports on the board,
        and applies the Aggregator's key share to generate a Partial Decryption Share.

        Args:
          baseline_BB: Map of baseline reports from Board.
          consumption_PBB: Map of consumption reports from Board.

        Returns:
            tuple: (Baseline_Partial_Shares, Consumption_Partial_Shares)
        """
        baseline_pk_to_part = {}
        consumption_pk_to_part = {}
        print(f"Number of participants to partially decrypt: {len(self.get_participants())}")
        print(f"Number of baseline reports on BB: {len(baseline_BB)}")
        print(f"Number of consumption reports on BB: {len(consumption_PBB)}")

        for pk_prime in self.get_participants():
            # Convert the EC Point to a string key for dict lookup
            pk_prime_str = str((pk_prime.x, pk_prime.y))
            
            # Process Baseline Report
            # Retrieve the encrypted baseline report from the Board using the anonymized key
            sm_baseline_t, sm_baseline_ct, sm_baseline_proof = baseline_BB[pk_prime_str]
            baseline_pk_to_part[pk_prime_str] = (
                self.pro.ahe.partial_decrypt(sm_baseline_ct, self.dk_share),
                sm_baseline_t,
                sm_baseline_proof
            )

            # Process Consumption Report
            # Retrieve and partially decrypt the consumption report similarly
            sm_consumption_t, sm_consumption_ct, sm_consumption_proof = consumption_PBB[pk_prime_str]
            consumption_pk_to_part[pk_prime_str] = (
                self.pro.ahe.partial_decrypt(sm_consumption_ct, self.dk_share),
                sm_consumption_t,
                sm_consumption_proof
            )
    
        # for proof of correct decryption on one of the commitments
        pk_prime_commitment = self.get_participants()[0]
        pk_prime_commitment_str = str((pk_prime_commitment.x, pk_prime_commitment.y))
        _, commitment_ct, _ = baseline_BB[pk_prime_commitment_str] 
        proof = prove_partial_decryption_share(self.pp, commitment_ct[0], self.dk_share)

        print(f"len baseline_pk_to_part: {len(baseline_pk_to_part)}")
        print(f"len consumption_pk_to_part: {len(consumption_pk_to_part)}")
        return (baseline_pk_to_part, consumption_pk_to_part), (commitment_ct, proof)
    
    def partial_dec_equal_cts(self, equal_cts):
        """
        Helper function to partially decrypt a list of specific ciphertexts.
        Often used for verifying the DSO's Noisy List.
        """
        partial_cts = []
        for ct in equal_cts:
            partial_ct = self.pro.ahe.partial_decrypt(ct, self.dk_share)
            partial_cts.append(partial_ct)

        
        return partial_cts