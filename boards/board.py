# this is both for public and private boards
from utils.signature import schnorr_verify, schnorr_verify_list
from utils.NIZKP import schnorr_NIZKP_verify
from utils.dec_proof import verify_correct_decryption
from utils.shuffle import CheckProof # TODO change name to be more specific like shuffle_verify_proof

class Board:
    
    def publish_dso_public_keys(self, dso_keys):
        
        # (pk, ek)
        (pk, pp, s_proof) = dso_keys[0]
        (ek, _, e_proof) = dso_keys[1]

        if not schnorr_NIZKP_verify(pk, pp, s_proof):
            print("DSO public key proof verification failed")
        
        # Report: write in the report how the test shows how the encryption can be decrypted etc
        if not verify_correct_decryption(ek, pp, e_proof):
            print("DSO encryption key proof verification failed")

        self.pk, self.ek = dso_keys
        
    # The DSO registers and has verified users and aggregators, then sends it to the board
    # TODO rewrite all schnorr_verify name to be schnorr_sign_verify for clarity
    def publish_smartmeters_and_aggregators(self, signed_lists):
        (
            self.register_smartmeter, sm_signatures, 
            self.register_aggregator, agg_signatures, 
            self.register_dr, dr_signatures
        ) = signed_lists

        sm_msg_list = [sm_id for sm_id, _ in self.register_smartmeter]
        agg_msg_list = [agg_id for agg_id, _ in self.register_aggregator]
        dr_msg_list = [dr_id for dr_id, _ in self.register_dr]
        
        sm_valid, sm_results = schnorr_verify_list(self.pk[0], self.pk[1], sm_msg_list, sm_signatures)
        if not sm_valid:
            print("Smartmeters were not verified")
            for i, msg, is_valid in sm_results:
                if not is_valid:
                    print(f"Smartmeter ID {msg} at index {i} failed verification.")
            return False
        
        agg_valid, agg_results = schnorr_verify_list(self.pk[0], self.pk[1], agg_msg_list, agg_signatures)
        if not agg_valid:
            print("Aggregators were not verified")
            for i, msg, is_valid in agg_results:
                if not is_valid:
                    print(f"Aggregator ID {msg} at index {i} failed verification.")
            return False
        
        dr_valid, dr_results =  schnorr_verify_list(self.pk[0], self.pk[1], dr_msg_list, dr_signatures)
        if not dr_valid:
            print("drs were not verified")
            for i, msg, is_valid in dr_results:
                if not is_valid:
                    print(f"dr ID {msg} at index {i} failed verification.")
            return False
        
        print("All smartmeters and aggregators were successfully verified.")
        return True

    def target_reduction(self, T_r):
        # the target reduction list is encrypted and signed by the DSO
        
        enc_T_r, signature = T_r
        
        if not schnorr_verify(self.pk[0], self.pk[1], enc_T_r, signature):
            print("target reduction list signature verification failed.")
            
        self.T_r = enc_T_r

    # mix
    # REPORT:
    # we had an issue here where we passed the entire self.register_smartmeter list which is (id, (pk, pp, proof)) to CheckProof
    # checkproof needs only the list of public keys (in the list e[]) to verify the shuffle proof
    # we use self.pk[1][1] as the generator g for the proof verification.
    # We use g because its a value both the prover and verifier agrees on, instead of a random pk from the list which may cause inconsistency
    def publish_mix_pk_and_proof(self, mix_data):
        pk_prime, πmix = mix_data
        self.mix_pk = pk_prime
        self.mix_proof = πmix

        # store e list to verify
        # Extract the list of public keys from the registered smart meters list e
        # TODO change the name e to something more descriptive
        e = [sm[1][0] for sm in self.register_smartmeter]
        # g is used for the proof generation (for its consistancy)
        # self.pk[1][1] = g
        is_valid = CheckProof(πmix, e, pk_prime, self.pk[1][1])
        
        if is_valid:
            print("Mixing proof verification succeeded")

    # Report: Should be sent through the anonym algorithm
    
    
    # IS THIS CORRECT? ISNT IT THE SAME AS publish_anonym_reports
    def publish_sm_reports(self, sm_reports):
        print(f"[] Publish anonym hashed reports on BB (not implemented)")
        self.sm_reports = sm_reports
        #[(pk, (t, cts, signature))] = sm_reports
        
        # pks = [report[0] for report in sm_reports]
        # msgs = [str((report[1][0], report[1][1])) for report in sm_reports]
        # signatures = [report[1][2] for report in sm_reports]

        # # pk, sec_params, msg_list, signatures
        # if not schnorr_verify_list(self.pk[0], self.pk[1], msgs, signatures):
        #     print("Smartmeters were not verified")
        
        # print("Published smartmeter reports:")
        # self.sm_reports = sm_reports

    def publish_participants(self, participants):
        self.participants = participants

    
    def publish_anonym_reports(self, anonym_reports, agg_id):
        hashed_reports, signature = anonym_reports
        
        agg_pk = None
        
        for id, pk in self.register_aggregator:
            if id == agg_id:
                agg_pk = pk
                break
        
        if not schnorr_verify(agg_pk[0], agg_pk[1], hashed_reports, signature):
            print("Anonymous key signature verification failed.")
            
        self.anonym = anonym_reports
        
    # pseudo-anonymous identities which are selected by the DR aggregator
    def publish_selected_sm(self, selected_w_sign, dr_agg_pk):
        selected, signature = selected_w_sign
        if not schnorr_verify(dr_agg_pk[0], dr_agg_pk[1], str(selected), signature):
            print("DR agg signature verification failed.")
        
        self.selected = selected

    # TODO the baseline should be gotten from report() this is only for temporary testing
    def publish_baselines(self, ct_b):
        self.ct_b = ct_b
        
        