# this is both for public and private boards
from utils.private_key_proof import schnorr_NIZKP_verify
from utils.elgamal_dec_proof import verify_correct_decryption
from utils.shuffle import Shuffle
from utils.signature import Signature


class Board:
    """ 
    Represents both the Draft Version paper's public and Private Bulletin Board.
    
    The Board serves as a trusted verifiable log. It makes all posted data auditable
    (signatures, proofs, shuffles). If verification fails the data is rejected.
    """
    
    def publish_dso_public_keys(self, dso_keys):
        """
        Publishes and verifies the DSO's keys.

        Args:
          dso_keys: A tuple containing:
             - Signing Key Package: (pk, pp, s_proof)
             - Encryption Key Package: (ek, pp, e_proof)

        """
        
        (pk, pp, s_proof) = dso_keys[0]
        (ek, _, e_proof) = dso_keys[1]

        # Verify that the DSO actually knows the private key for this public key
        if not schnorr_NIZKP_verify(pk, pp, s_proof):
            print("DSO public key proof verification failed")

        self.sig = Signature()

        self.pk, self.ek = dso_keys
        self.sm_eval_status = {}
        
    def publish_smartmeters_and_aggregators(self, signed_lists):
        """
        Publishes the list of registered entities, verified by the DSO's signature.

        Args:
          signed_lists: tuple containing:
             - SM_List, SM_Signatures
             - Agg_List, Agg_Signatures
             - DR_List, DR_Signatures
        
        Returns:
            bool: True if all lists are correctly signed by the DSO; False otherwise.
        """
        (
            self.register_smartmeter, sm_signatures, 
            self.register_aggregator, agg_signatures, 
            self.register_dr, dr_signatures
        ) = signed_lists

        sm_msg_list = [sm_id for sm_id, _ in self.register_smartmeter]
        agg_msg_list = [agg_id for agg_id, _ in self.register_aggregator]
        dr_msg_list = [dr_id for dr_id, _ in self.register_dr]
        
        # Verify DSO signatures on the Smart Meter list
        sm_valid, sm_results = self.sig.schnorr_verify_list(self.pk[0], self.pk[1], sm_msg_list, sm_signatures)
        if not sm_valid:
            print("Smartmeters were not verified")
            for i, msg, is_valid in sm_results:
                if not is_valid:
                    print(f"Smartmeter ID {msg} at index {i} failed verification.")
            return False
        
        # Verify DSO signatures on the Aggregator list
        agg_valid, agg_results = self.sig.schnorr_verify_list(self.pk[0], self.pk[1], agg_msg_list, agg_signatures)
        if not agg_valid:
            print("Aggregators were not verified")
            for i, msg, is_valid in agg_results:
                if not is_valid:
                    print(f"Aggregator ID {msg} at index {i} failed verification.")
            return False
        
        # Verify DSO signatures on the DR Aggregator list
        dr_valid, dr_results =  self.sig.schnorr_verify_list(self.pk[0], self.pk[1], dr_msg_list, dr_signatures)
        if not dr_valid:
            print("drs were not verified")
            for i, msg, is_valid in dr_results:
                if not is_valid:
                    print(f"dr ID {msg} at index {i} failed verification.")
            return False
        
        print("All smartmeters and aggregators were successfully verified.")
        return True

    def publish_target_reduction(self, T_r):
        """
        Publishes the encrypted target reduction list (Noisy List).

        Args:
          T_r: tuple(Encrypted_List, Signature)
        """
        enc_T_r, signature = T_r
        
        if not self.sig.schnorr_verify(self.pk[0], self.pk[1], enc_T_r, signature):
            print("target reduction list signature verification failed.")
            
        self.T_r = enc_T_r
    
    def get_target_reduction(self):
        return self.T_r

    def publish_mix_pk_and_proof(self, mix_data):
        """
        Verifies and publishes the result of the Mix() shuffle.
        
        This checks the Zero-Knowledge Proof that the output list `pk_prime` is a 
        valid permutation and re-randomization of the input keys.

        Args:
          mix_data: tuple(Shuffled_PKs, Shuffle_Proof_Object)
        """
        pk_prime, πmix = mix_data
        self.mix_pk = pk_prime
        
        shuffle = Shuffle(self.pk[1])
        
        # store e list to verify
        # Extract the list of public keys from the registered smart meters list e
        e = [sm[1][0] for sm in self.register_smartmeter]
        
        if not shuffle.verify_shuffle_proof(πmix, e, pk_prime, self.pk[1][1]):
            print("Mixing proof verification FAILED")
        self.mix_proof = πmix

    def publish_participants(self, participants):
        """
        Stores the list of anonymized participants available for selection.

        Args:
          participants (list[EcPt]): List of anonymized public keys.
        """
        self.participants = participants

    def get_participants(self):
        """
        Returns the participants as a list (used by eval)

        return:
            list
        """
        return self.participants
    
    # Report: Should be sent through the anonym algorithm
    def publish_anonym_reports(self, anonym_reports, agg_id):
        """
        Publishes the batch of anonymized baseline reports.
        Verifies the Aggregator's signature on the batch hash.

        Args:
          anonym_reports: tuple(Hash_of_Batch, Signature)
          agg_id: str ID of the aggregator who compiled this.
        """
        hashed_reports, signature = anonym_reports
        
        agg_pk = None
        
        for id, pk in self.register_aggregator:
            if id == agg_id:
                agg_pk = pk
                break
        
        if not self.sig.schnorr_verify(agg_pk[0], agg_pk[1], hashed_reports, signature):
            print("Anonymous key signature verification failed.")
            
        self.anonym = anonym_reports
    
    # Anonym user consumption reports from 
    def publish_anonym_reports_PBB(self, anonym_reports):
        """
        Stores the actual content of the anonymized baseline reports into a map.

        Args:
          anonym_reports: list of tuples (pk_prime, ciphertext, timestamp, proof)
        """

        self.anonym_report_map = {}  # pk' -> (t, ct_c, σ)
        
        for pk_prime, ct, t, proof in anonym_reports:
            pk_key = str((pk_prime.x, pk_prime.y))
            self.anonym_report_map[pk_key] = (t, ct, proof)

        self.anonym_reports = anonym_reports
        
    def publish_selected_sm(self, selected_w_sign):
        """
        Publishes the list of Smart Meters selected for the DR event.
        Verifies the DR Aggregator's signature.

        Args:
          selected_w_sign: tuple(List_of_Selected_PKs, Signature, DR_Aggregator_PK)
        """
        selected, signature, dr_agg_pk = selected_w_sign
        if not self.sig.schnorr_verify(dr_agg_pk[0], dr_agg_pk[1], str(selected), signature):
            print("DR agg signature verification failed.")
        
        self.selected = selected

    def get_selected_sm(self):
        """ 
        List of anonymized public keys selected for the event

        return:
            list
        """
        return self.selected

    # the baseline
    def get_sm_baseline(self):
        """
        Retrieves the baseline reports map, used as a test for eval
        
        Returns:
            dict: Map of {pk_string: (timestamp, ciphertext, proof)}
        """
        return self.anonym_report_map

    def publish_sm_comsumption_PBB(self, consumption_report):
        """
        Stores the consumption reports for the event (after the event occurs).

        Args:
            consumption_report: list of tuples (pk_prime, ciphertext, timestamp, proof)
        """

        self.consumption_report_map = {}
        for pk_prime, ct, t, proof in consumption_report:
            pk_key = str((pk_prime.x, pk_prime.y))
            self.consumption_report_map[pk_key] = t, ct, proof

        # not sure if needed
        self.sm_consumptions = consumption_report

    def get_sm_consumption(self):
        """ 
        Returns the map of consumption reports.
        """
        return self.consumption_report_map