import time
from src.utils.elgamal_dec_proof import hash_to_int
from src.utils.ec_elgamal import ElGamal
import threshold_crypto as tc

class Eval:
    """
    Handles the privacy-preserving evaluation of the Demand Response event.
    
    This class performs operations on encrypted data (homomorphic subtraction, aggregation)
    and executes the Private Equality Test (PET) to determine if the total reduction 
    matched the target, without decrypting individual user data.

    references:
        - Draft Version Paper
    """
    def __init__(self, dso_ek):
        """
        Args:
            dso_ek (tuple): The system-wide ElGamal encryption key.
        """
        self.dso_ek = dso_ek
        self.el = ElGamal()

    def collapse(self, cipher_list):
        """
        Helper function that collapses a list of ciphertexts into a single ciphertext
        by applying weights (powers of 2) to each ciphertext and summing them.

        This is done to convert bit-wise encrypted values into a single encrypted integer.

        Args:
            cipher_list (list): List of ciphertexts [(C1, C2), ...]
        Returns:
            tuple: Collapsed ciphertext (C1_total, C2_total)
        """
        total_a, total_b = None, None
        for i, (a, b) in enumerate(cipher_list):
            weight = 2**i
            # Scalar multiplication: weight * Point
            weighted_a = a * weight 
            weighted_b = b * weight
            
            if total_a is None:
                total_a, total_b = weighted_a, weighted_b
            else:
                total_a += weighted_a
                total_b += weighted_b
                
        return total_a, total_b
    
    def sub(self, c1, c2):
        """
        Helper function that computes the homomorphic subtraction of two encrypted values.

        Args:
            c1 (list): Ciphertext of Baseline [(C1, C2), ...] or a tuple (C1, C2)
            c2 (list): Ciphertext of Consumption [(C1, C2), ...] or a tuple (C1, C2)

        Returns:
            list: Encrypted difference [(C1, C2), ...]
        """
        #if c1 is not a list
        if isinstance(c1, list):
            a1, b1 = self.collapse(c1)
        else:
            a1, b1 = c1

        if isinstance(c2, list):
            a2, b2 = self.collapse(c2)
        else:
             a2, b2 = c2
        
        return (a1 + (-a2), b1 + (-b2))
    
    def add(self, c1, c2):

        a1, b1 = c1
        a2, b2 = c2
        
        return (a1 + a2, b1 + b2)

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
        target_reduction = BB.get_target_reduction()
        baseline_BB = BB.get_sm_baseline()
        consumption_PBB = PBB.get_sm_consumption()

        # lists
        participants = BB.get_participants()
        selected = BB.get_selected_sm()
        
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
            
            baseline = self.el._eval_threshold_decrypt(
                (sm_baseline_ct_part_agg + sm_baseline_ct_part_dr),
                sm_baseline_ct
            )
            
            # partial decryption of the consumption
            sm_consumption_ct_part_agg, _, _ = agg_consumptions_parts[pk_prime_str]
            sm_consumption_ct_part_dr, _, _ = dr_consumptions_parts[pk_prime_str]

            consumption = self.el._eval_threshold_decrypt(
                (sm_consumption_ct_part_agg + sm_consumption_ct_part_dr),
                sm_consumption_ct
            )

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
        ct_eq, π_eq = self.pet_comparison(ct_sum, target_reduction)
        
        return ct_eq, π_eq
    
    def final_check_eval(self, BB, PBB, agg_share, dr_share, ct_target_consumption_comparison_w_proof, thresh_param, target_print):
        """
        Finalizes the evaluation by checking the result of the Private Equality Test (PET).
        
        It combines the partial decryption shares of the PET result. 
        - If the result decrypts to the Identity Point (0), the Target was Met.
        - If it decrypts to a random point, the Target was Not Met.
        """
        ct_target_consumption_comparison, proof = ct_target_consumption_comparison_w_proof

        print(f"\n\n len of ct_target_consumption_comparison {len(ct_target_consumption_comparison)} \n\n")

        # Partial decryption
        M_set_final, proof_shar = self.combine_decryption_shares(agg_share, dr_share, ct_target_consumption_comparison, thresh_param)
        
        print(f"\nEvaluation complete\n")
        print(f"selected with consumption below their baseline: {len(self.eval_results)}")
        print(f"participants not selected or did not meet baseline: {len(self.for_marked_or_not_selected)}\n")
        # print(f" target comparisons {len(ct_target_consumption_comparison)}")
        print(f"Final M_set: \n{M_set_final}")
        print(f"Target reduction list: \n{target_print}")
        print(f"\n eval done")

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

    def ct_reduction(self, ct_b, ct_c):
        """
        Computes the Energy Reduction.
        
        Formula: Reduction = Baseline - Consumption
        
        Returns:
            list: Encrypted reduction list.
        """
        ct_diff_tuple = self.sub(ct_b, ct_c)

        return ct_diff_tuple

    def ct_aggregation(self, reduc_set):
        """
        Homomorphic Aggregation of Reductions.
        
        Sums all individual encrypted reductions into a single total encrypted reduction.
        
        Args:
            reduc_set (list): List of encrypted reductions.

        Returns:
            tuple: (Total_C1, Total_C2)
        """
        CT_prod = reduc_set[0][0]
        for i in range(1, len(reduc_set)):
            CT_i = reduc_set[i][0]
            CT_prod = self.add(CT_prod, CT_i)
            
        return CT_prod

    def pet_comparison(self, ct_sum, ct_t_list):
        """
        Executes the Private Equality Test (PET) for multiple targets (e.g., Noisy List).
        
        Checks if Total_Reduction == Target_Reduction.
        Iterates through all possible targets in `ct_t_list` (the noisy list) and calls `epet` for each.
        
        Returns:
            tuple: (List_of_EQ_Ciphertexts, List_of_Proofs)
        """
        ct_eq = []
        ct_eq, π_r = self.epet(ct_sum, ct_t_list)
        verify_r_proof = self.verify_r(ct_sum, ct_t_list, ct_eq, π_r)

        if not verify_r_proof:
            raise ValueError("Proof of knowledge for 'r' failed verification.")

        return (ct_eq, π_r)

    def epet(self, ct_sum, ct_t_list):
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

        ct_eq_list = []
        
        # Since ct_t_list is a list of tuples (bit-wise encryption), we iterate through it to extract each tuple
        for ct_t in ct_t_list:
            ct_diff = self.sub(ct_sum, ct_t)

            ct1_diff, ct2_diff = ct_diff
            ct1_eq = int(r) * ct1_diff
            ct2_eq = int(r) * ct2_diff
            
            ct_eq_list.append((ct1_eq, ct2_eq))

        # pass the lists ct_sum and ct_t_list with proof_r
        π_r_i = self.proof_r(ct_sum, ct_t_list, ct_eq_list, r)

        return (ct_eq_list, π_r_i)

    def proof_r(self, ct1, ct2, ct_eq, witness):
        """
        Generates a NIZKP proving knowledge of the random scalar 'r' used in the EPET.
        
        Proves: C_eq = (C_sum - C_target)^r
        This ensures the aggregator didn't just encrypt "0" directly to fake a success.
        
        Returns:
            tuple: (Commitments, Response, Challenge)
        """
        order = self.dso_ek[1][2]
        r = tc.number.random_in_range(1, order)

        A_values = []

        for ct2_i in ct2:
            ct_diff = self.sub(ct1, ct2_i)

            c1_diff, c2_diff = ct_diff
            
            c1_A = int(r) * c1_diff
            c2_A = int(r) * c2_diff

            A_values.append((c1_A, c2_A))

        challenge = hash_to_int(self.dso_ek, ct1, ct2, ct_eq, A_values, order=order)

        response = (int(r) + int(challenge) * int(witness)) % int(order)

        return (A_values, response, challenge)

    def verify_r(self, ct1, ct2, ct_eq, proof):
        """
        Verifies the NIZKP for the scalar 'r'.
        
        Returns:
            bool: True if verification succeeds.
        """
        order = self.dso_ek[1][2]

        A_values, response, challenge = proof

        c_check = hash_to_int(self.dso_ek, ct1, ct2, ct_eq, A_values, order=order)

        for (A1, A2), ct_t_i, (c1_eq, c2_eq) in zip(A_values, ct2, ct_eq):
            ct_diff = self.sub(ct1, ct_t_i)

            c1_diff, c2_diff = ct_diff

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
        print("Attempting to combine decryption shares...")
        
        # Define Identity Point
        identity_point = 0 * self.dso_ek[1][1]
        M_set_final = []
        
        for i in range(len(ct_eq_list)):
            ct_eq_i = ct_eq_list[i] # list of tuples [(C1_eq, C2_eq)]
            
            agg_partial_i = agg_share[i]
            dr_partial_i = dr_share[i]
            combined_partial = [agg_partial_i, dr_partial_i]
            
            plaintext_point = self.el.threshold_decrypt_point(
                combined_partial, 
                ct_eq_i,  # Pass tuple (C1, C2) directly
            )

            if plaintext_point == identity_point:
                M_set_final.append(1)  # Target met (Diff == 0)
            else:
                M_set_final.append(0)  # Target not met (Diff != 0)
            
        pi_dec_proofs = ["placeholder_proof_of_decryption_share"] * len(ct_eq_list)
        return M_set_final, pi_dec_proofs