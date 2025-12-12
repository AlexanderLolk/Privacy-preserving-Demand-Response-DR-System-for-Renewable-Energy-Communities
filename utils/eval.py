import time
from utils.elgamal_dec_proof import hash_to_int
from utils.ec_elgamal import ElGamal
import threshold_crypto as tc

class Eval:
    """
    Handles the privacy-preserving evaluation of the Demand Response event.
    
    This class performs operations on encrypted data (homomorphic subtraction, aggregation)
    and executes the Private Equality Test (PET) to determine if the total reduction 
    matched the target, without decrypting individual user data.
    """
    def __init__(self, dso_ek):
        """
        Args:
            dso_ek (tuple): The system-wide ElGamal encryption key.
        """
        self.dso_ek = dso_ek

    def sub(self, c1, c2):
        """
        Helper function that computes the homomorphic subtraction of two encrypted values.

        Args:
            c1 (list): Ciphertext of Baseline [(C1, C2), ...]
            c2 (list): Ciphertext of Consumption [(C1, C2), ...]

        Returns:
            list: Encrypted difference [(C1, C2), ...]
        """

        a1, b1 = c1
        a2, b2 = c2
        
        return (a1 + (-a2), b1 + (-b2))

    def eval(self, BB, PBB, agg_share, dr_share):
        """
        Main Evaluation Protocol.
        
        - Retrieves encrypted Baseline and Consumption reports.
        - Combines partial decryption shares from Aggregators to recover plaintext values (in this simulation).
        - Performs Order Comparison: Checks if Consumption < Baseline.
        - Calculates Reduction: (Baseline - Consumption).
        - Aggregates reductions: Sum(Reductions).
        - performs PET: Checks if Sum >= Target.

        Args:
            BB: The Board instance (Baseline reports).
            PBB: The Private Bulletin Board instance (Consumption reports).
                Note: the BB and PBB are both in board.py
            agg_share: Partial decryption shares from Energy Aggregator.
            dr_share: Partial decryption shares from DR Aggregator.
            threshold_param: Parameters for threshold decryption.

        Returns:
            tuple: (Encrypted_Result_List, Proofs)
                   The result is a list of ciphertexts that encrypt '0' if success, or random if fail.
        """
        print("\nin eval")
        
        target_reduction = BB.get_target_reduction()
        baseline_BB = BB.get_sm_baseline()
        consumption_PBB = PBB.get_sm_consumption()

        # lists
        participants = BB.get_participants()
        selected = BB.get_selected_sm()

        self.el = ElGamal()
        
        agg_baselines_parts, agg_consumptions_parts = agg_share
        dr_baselines_parts, dr_consumptions_parts = dr_share

        self.for_marked_or_not_selected = []
        self.eval_results = []
        CT_red = []

        for pk_prime in participants:
            pk_prime_str = str((pk_prime.x, pk_prime.y))
            sm_baseline_t, sm_baseline_ct, sm_baseline_proof = baseline_BB[pk_prime_str]
            sm_consumption_t, sm_consumption_ct, sm_consumption_proof = consumption_PBB[pk_prime_str]

            # partial decryption of the baseline
            sm_baseline_ct_part_agg, _, _ = agg_baselines_parts[pk_prime_str]
            sm_baseline_ct_part_dr, _, _ = dr_baselines_parts[pk_prime_str]
            
            baseline = self.el._eval_threshold_decrypt((sm_baseline_ct_part_agg + sm_baseline_ct_part_dr), sm_baseline_ct)
            
            # partial decryption of the consumption
            sm_consumption_ct_part_agg, _, _ = agg_consumptions_parts[pk_prime_str]
            sm_consumption_ct_part_dr, _, _ = dr_consumptions_parts[pk_prime_str]

            consumption = self.el._eval_threshold_decrypt((sm_consumption_ct_part_agg + sm_consumption_ct_part_dr), sm_consumption_ct)

            # Order comparison (ord)
            # Note: ct_o is not ciphertext
            ct_o, t, ord_proof = self.ord_comparison(baseline, consumption)
        
            if pk_prime not in selected or ct_o < 1:
                self.for_marked_or_not_selected.append((ct_o, t, pk_prime, ord_proof))
                continue 

            # Ct Reduction
            ct_red = self.ct_reduction(sm_baseline_ct, sm_consumption_ct)
            if ct_red is None:
                self.for_marked_or_not_selected.append((ct_o, t, pk_prime, ord_proof))
                continue 
            
            self.eval_results.append((ct_o, t, pk_prime, ord_proof))
            
            CT_red.append((ct_red, t, pk_prime))

        if len(CT_red) < 1:
            return [], []
        
        # Aggregation
        ct_sum = self.ct_aggregation(CT_red)
        
        # PET comparison
        print(f"Aggregator computing new PET (ct_eq) and publishing to Board.")
        ct_eq, π_eq = self.pet_comparison(ct_sum, target_reduction)
        
        return ct_eq, π_eq
    
    def final_check_eval(self, BB, PBB, agg_share, dr_share, ct_target_consumption_comparison_w_proof, thresh_param):
        """
        Finalizes the evaluation by checking the result of the Private Equality Test (PET).
        
        It combines the partial decryption shares of the PET result. 
        - If the result decrypts to the Identity Point (0), the Target was Met.
        - If it decrypts to a random point, the Target was Not Met.
        """
        ct_target_consumption_comparison, proof = ct_target_consumption_comparison_w_proof

        # Partial decryption
        M_set_final, proof_shar = self.combine_decryption_shares(agg_share, dr_share, ct_target_consumption_comparison, thresh_param)
        
        print(f"\nEvaluation complete\n")
        print(f" participants marked: {len(self.eval_results)}")
        print(f" participants not selected or did not meet baseline: {len(self.for_marked_or_not_selected)}\n")
        print(f" target comparisons {len(ct_target_consumption_comparison)}")
        print(f" Final M_set: {M_set_final}")
        print(f" eval done")

        return BB

    def ord_comparison(self, baseline, consumption):
        """
        Placeholder for Order Comparison of two values.
        
        [Intended Logic]: Securely computes if Enc(Consumption) < Enc(Baseline) without decrypting.
        [Current Simulation]: Uses decrypted plaintext values to return 1 (True) or 0 (False).
        
        Returns:
            tuple: (Result_Bit, Timestamp, Proof_Placeholder)
        """
        t = int(time.time())
        result = None
        if (consumption < baseline):
            result = 1
        else:
            result = 0

        ord_proof = "ord_proof not implemented"

        return result, t, ord_proof

    def ct_reduction(self, ct_bs, ct_cs):
        """
        Computes the Energy Reduction.
        
        Formula: Reduction = Baseline - Consumption
        
        Returns:
            list: Encrypted reduction list.
        """
        ct_diff_list = []
        for ct_b, ct_c in zip(ct_bs, ct_cs):
            ct_diff_tuple = self.sub(ct_b, ct_c)
            ct_diff_list.append(ct_diff_tuple)
        
        return ct_diff_list

    def ct_aggregation(self, reduc_set):
        """
        Homomorphic Aggregation of Reductions.
        
        Sums all individual encrypted reductions into a single total encrypted reduction.
        
        Args:
            reduc_set (list): List of encrypted reductions.

        Returns:
            tuple: (Total_C1, Total_C2)
        """

        C1_prod, C2_prod = reduc_set[0][0][0]

        for i in range(1, len(reduc_set)):
            for j in range(1, len(reduc_set[i][0])):
                C1_i, C2_i = reduc_set[i][0][j]

                C1_prod = C1_prod + C1_i
                C2_prod = C2_prod + C2_i
            
        return (C1_prod, C2_prod)

    def pet_comparison(self, ct_sum, ct_T):
        """
        Executes the Private Equality Test (PET) for multiple targets (e.g., Noisy List).
        
        Checks if Total_Reduction == Target_Reduction.
        Iterates through all possible targets in `ct_T` (the noisy list) and calls `epet` for each.
        
        Returns:
            tuple: (List_of_EQ_Ciphertexts, List_of_Proofs)
        """
        ct_eq = []
        π_eq = []

        # for ct_T_i in ct_T:
        #     ct_eq_i, π_r_i = self.epet(ct_sum, ct_T_i)
        #     ct_eq.append(ct_eq_i)
        #     π_eq.append(π_r_i)

        ct_eq_i, π_r_i = self.epet(ct_sum, ct_T)
        ct_eq.append(ct_eq_i)
        π_eq.append(π_r_i)

        return (ct_eq, π_eq)

    def epet(self, ct_sum, ct_t_i):
        """
        Encrypted Private Equality Test (EPET) logic.
        
        Computes a ciphertext that decrypts to 0 if Sum == Target.
        Formula: C_eq = (Sum - Target) * r
        
        - If Sum == Target: (Sum - Target) is 0. 0 * r = 0. Result is Enc(0).
        - If Sum != Target: (Sum - Target) is X. X * r is Random. Result is Enc(Random).
        
        Args:
            ct_sum: Total Aggregated Reduction (Ciphertext).
            ct_t_i: One specific target value from the Noisy List (Ciphertext).

        Returns:
            tuple: (C_eq, Proof_of_r)
        """

        order = self.dso_ek[1][2]
        
        r = tc.number.random_in_range(1, order)

        ct_eq = []
            
        # Since ct_t_i is a list of typles (bit-wise encryption), we iterate through it to extract each tuple
        for (c1_t, c2_t) in ct_t_i:
            c1_sum, c2_sum = ct_sum

            c1_diff = c1_sum + (-c1_t)
            c2_diff = c2_sum + (-c2_t)

            c1_eq = int(r) * c1_diff
            c2_eq = int(r) * c2_diff

            ct_eq.append((c1_eq, c2_eq))

        # pass the lists ct_sum and ct_t_i with proof_r
        π_r_i = self.proof_r(ct_sum, ct_t_i, ct_eq, r)

        return (ct_eq, π_r_i)

    def proof_r(self, ct1, ct2, ct_eq, witness):
        """
        Generates a NIZKP proving knowledge of the random scalar 'r' used in the EPET.
        
        Proves: C_eq = (C_sum - C_target)^r
        This ensures the aggregator didn't just encrypt "0" directly to fake a success.
        
        Returns:
            tuple: (Commitments, Response, Challenge)
        """
        g = self.dso_ek[1][1]
        order = self.dso_ek[1][2]
        r = tc.number.random_in_range(1, order)

        # tuples
        c1_sum, c2_sum = ct1

        A_values = []
        for (c1_t, c2_t) in ct2:
            c1_diff = c1_sum + (-c1_t)
            c2_diff = c2_sum + (-c2_t)
            
            c1_A = int(r) * c1_diff
            c2_A = int(r) * c2_diff

            A_values.append((c1_A, c2_A))

        challenge = hash_to_int(g, self.dso_ek, ct1, ct2, ct_eq, A_values, order=order)

        response = (int(r) + int(challenge) * int(witness)) % int(order)

        return (A_values, response, challenge)

    def verify_r(self, ct1, ct2, ct_eq, proof):
        """
        Verifies the NIZKP for the scalar 'r'.
        
        Returns:
            bool: True if verification succeeds.
        """
        g = self.dso_ek[1][1]
        order = self.dso_ek[1][2]

        A_values, response, challenge = proof

        # tuples
        c1_sum, c2_sum = ct1

        c_check = hash_to_int(g, self.dso_ek, ct1, ct2, ct_eq, A_values, order=order)

        for (A1, A2), (c1_t, c2_t), (c1_eq, c2_eq) in zip(A_values, ct2, ct_eq):
            c1_diff = c1_sum + (-c1_t)
            c2_diff = c2_sum + (-c2_t)

            V1 = int(response) * c1_diff
            V2 = int(response) * c2_diff

            check1 = (V1 == A1 + (int(challenge) * c1_eq))
            check2 = (V2 == A2 + (int(challenge) * c2_eq))

            if not (check1 and check2):
                return False

        return int(challenge) == int(c_check)

    def combine_decryption_shares(self, agg_share, dr_share, ct_eq_list, thresh_params):
        """
        Combines the threshold decryption shares for the PET result.
        
        If the combined decryption yields the Identity Point (0),
        it means the PET was successful (Reduction == Target).
        
        Returns:
            list: List of 1s (Success) and 0s (Fail) for each target compared.
        """
        print("\nin combine_decryption_shares")
        print("Attempting to combine decryption shares...")

        g = self.dso_ek[1][1]
        
        # Define Identity Point (0*G)
        identity_point = 0 * g
        
        M_set_final = []

        for i in range(len(ct_eq_list)):
            # Get partial decryptions for ciphertext i from all aggregators
            ct_eq_i = ct_eq_list[i] # list of tuples

            agg_partial_i = agg_share[i]
            dr_partial_i = dr_share[i]
            
            combined_partial = agg_partial_i + dr_partial_i
            
            plaintext_point = self.el.threshold_decrypt(
                combined_partial, 
                ct_eq_i,  # Pass tuple (C1, C2) directly
                thresh_params
            )
            
            if plaintext_point == identity_point:
                M_set_final.append(1)  # Target met (Diff == 0)
            else:
                M_set_final.append(0)  # Target not met (Diff != 0)
            
        pi_dec_proofs = ["placeholder_proof_of_decryption_share"] * len(ct_eq_list)
        return M_set_final, pi_dec_proofs