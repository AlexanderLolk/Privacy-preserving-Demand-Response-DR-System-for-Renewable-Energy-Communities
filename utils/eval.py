from utils.dec_proof import hash_to_bn
from utils.generators import pub_param
import threshold_crypto as tc

#####
# Eval() outputs an evaluation and showcases which users have met the target reduction
# example:
# M_set = [1,0,1,1,0] means that user 0,2,3 have met the target reduction
# user 1 and 4 have not met the target reduction

# Helper function to calculate subtraction of two ciphertexts
def sub(c1, c2):
    """
    Computes Enc(m1 - m2) given Enc(m1) and Enc(m2) by using the 
    additive property of Elliptic Curve ElGamal (C1 * C2^-1)
    """
    a1, b1 = c1
    a2, b2 = c2
    return (a1 + (-a2), b1 + (-b2))

#=============
# Eval(BB, PBB, dk_share, agg_id, dso_ek) → (PBB, BB)
# with threshold decryption
#=============

# takes dk_share and agg_id instead of full dk
# Takes this aggregator's 'dk_share' and 'agg_id'
def eval(BB, PBB, dk_share, dso_ek, agg_id):
    """
    Retrieves reports, computes individual reductions, aggregates them, 
    and initiates the threshold decryption process to verify targets
    """
    # list of cts
    # ct_b: baseline ciphertexts from BB
    ct_b = getattr(BB, "ct_b", None)
    if ct_b is None:
        print("Public board missing baseline ciphertexts (ct_b).")
        return (PBB, BB)

    # ct_t: consumption reports from PBB
    consumption_reports = getattr(PBB, "ct_t", None)
    if consumption_reports is None:
        print("Private board missing consumption reports (ct_t).")
        return (PBB, BB)

    try:
        ct_T = BB.ct_T
    except AttributeError:
        print("No ct_T found in BB during Eval")
        return (PBB, BB)
    
    # lists
    eval_results_step1 = [] 
    CT_red = [] 

    # Steps 1, 2, 3: Loop and call placeholders
    for pk_prime, report_data in consumption_reports.items():
        t = report_data[0]
        ct_m = report_data[1] 

        # step 1:ord comparison
        ct_o, ord_proof = ord_comparison(ct_b, ct_m)
        eval_results_step1.append((ct_o, t, pk_prime, ord_proof))

        # step 2 ct reduction
        ct_red = ct_reduction(ct_b, ct_m, ct_o) 

        # step 3 set CT_red
        CT_red.append((ct_red, t, pk_prime))

    # step 4: Aggregation
    ct_sum = ct_aggregation(CT_red)
    BB.ct_sum = ct_sum

    # STEP 5: PET COMPARISON
    # Check if ct_eq already exists on the board.
    # If it does, we'll use the existing one so all aggregators 
    # decrypt the same ciphertext.
    
    existing_ct_eq = getattr(BB, "ct_eq", None)
    
    if existing_ct_eq is not None:
        print(f"Aggregator {agg_id} using existing ct_eq from Public Board.")
        ct_eq = existing_ct_eq
        # verify BB.π_eq here normally
        π_eq = getattr(BB, "π_eq", None)

        if π_eq is None or len(π_eq) != len(ct_eq):
            print("Error: Missing proofs on board.")
            return (PBB, BB)

        # VERIFY THE PROOFS
        # We check that ct_eq correctly represents (ct_sum - ct_T)^r
        all_valid = True
        for i in range(len(ct_eq)):
            # verify_r(ct_sum, ct_target, ct_result, proof, pub_key)
            if not verify_r(ct_sum, ct_T[i], ct_eq[i], π_eq[i], dso_ek):
                print(f"Verification failed for target {i}")
                all_valid = False
                break
        
        if not all_valid:
            print(f"Aggregator {agg_id} rejected the calculation.")
            return (PBB, BB)
            
        print(f"Aggregator {agg_id} successfully verified all PET proofs.")

    else:
        print(f"Aggregator {agg_id} computing new PET (ct_eq) and publishing to Board.")
        ct_eq, π_eq = pet_comparison(ct_sum, ct_T, dso_ek)
        
        # Publish immediately so the next aggregator uses this one
        BB.ct_eq = ct_eq
        BB.π_eq = π_eq
        BB.eval_results = eval_results_step1 

    # STEP 6: PARTIAL DECRYPTION
    # Call partial_decrypt with agg's share
    M_shares_list, π_dec_share = partial_decrypt(ct_eq, dk_share)
    
    #####
    # Update the boards with eval results
    
    # Store the aggregators partial share on the board
    if not hasattr(BB, "M_shares"):
        BB.M_shares = {}
    if not hasattr(BB, "pi_dec_shares"):
        BB.pi_dec_shares = {}

    # Publish the agg's share, labeled by its ID
    BB.M_shares[agg_id] = M_shares_list
    BB.pi_dec_shares[agg_id] = π_dec_share
    
    BB.eval_status = "evaluated_partial_decryption"

    # private board
    PBB.eval_data = {
        "ct_b": ct_b,
        "consumption_reports": consumption_reports,
        "dk_share": "hidden" 
    }
    
    return (PBB, BB)

# (cto, t, pk′, πord) ← ord(ctb, ctm)
def ord_comparison(ct_b, ct_m):
    """
    (for step 1) Order Comparison of two ciphertexts.
    [Intended] Should return Enc(1) if Consumption < Baseline, else Enc(0).
    Requires NIZKP.
    
    [Current] Placeholder: Returns Enc(0) (Identity) and a placeholder string.
    """
    pp = pub_param()
    g = pp.P
    identity_point = 0 * g
    ct_o = (identity_point, identity_point)

    ord_proof = "ord_proof not implemented" # placeholder
    return ct_o, ord_proof

# ctred ← Reduct(ct_b, c_tm, ct_o)
def ct_reduction(ct_b, ct_m, ct_o):
    """
    (for step 2) Conditional Reduction Calculation.
    [Intended] Should compute Enc((Baseline - Consumption) * ct_o).
    Requires homomorphic multiplication to apply the condition.
    [Current] Placeholder: Returns Enc(0) (Identity point).
    Does not perform subtraction; assumes 0 reduction.
    """
    pp = pub_param()
    g = pp.P
    identity_point = 0 * g
    ct_red = (identity_point, identity_point)
    return ct_red

# ctsum ← Agg(ct_red)
def ct_aggregation(reduc_set):
    """
    (for step 4) Homomorphic Aggregation.
    Sums all individual reductions into a single ciphertext (ct_sum).
    Uses the additive homomorphic property (for Ec).
    """
    C1_prod, C2_prod = reduc_set[0][0]
    for i in range(1, len(reduc_set)):
        C1_i, C2_i = reduc_set[i][0]
        C1_prod = C1_prod + C1_i
        C2_prod = C2_prod + C2_i
    return (C1_prod, C2_prod)

# (cteq, πeq ) ← Pet(ctsum, ctT )
def pet_comparison(ct_sum, ct_T, dso_ek):
    """
    (for step 5) Private Equality Test
    Iterates through targets (ct_T) to compare against ct_sum (to verify reductions).
    Calls epet for each target.
    """
    ct_eq = []
    π_eq = []

    for ct_T_i in ct_T:
        ct_eq_i, π_r_i = epet(ct_sum, ct_T_i, dso_ek)
        ct_eq.append(ct_eq_i)
        π_eq.append(π_r_i)

    return (ct_eq, π_eq)

# (ct_eq_i, π_r_i) ← Epet(ct_sum, ct_T_i)
def epet(ct_sum, ct_t_i, dso_ek):
    """
    Encrypted Private Equality Test (EPET) (page 19 in given report)
    Computes Enc(r * (Sum - Target)).
    If Sum == Target, result is Enc(0). If not, result is Enc(Random).
    Includes generation of proof 'r'.
    This uses the non-interactive zero-knowledge proof (NIZKP) proof_r
    """
    pp = pub_param()
    g = pp.P
    order = pp.order
    
    r = tc.number.random_in_range(1, order)

    ct_diff = sub(ct_sum, ct_t_i)
    (C1_diff, C2_diff) = ct_diff

    C1_eq = int(r) * C1_diff
    C2_eq = int(r) * C2_diff
    ct_eq = (C1_eq, C2_eq)

    π_r_i = proof_r(ct_sum, ct_t_i, ct_eq, r, dso_ek)

    return (ct_eq, π_r_i)

def proof_r(ct1, ct2, ct_eq, r, dso_ek):
    """
    NIZKP for r used in EPET
    Proves knowledge of the random Bn r used in EPET
    """
    pp = pub_param()
    g = pp.P
    order = pp.order

    C1_1, C2_1 = ct1
    C1_2, C2_2 = ct2

    C1_eq, C2_eq = ct_eq

    ct_diff = sub(ct1, ct2)
    C1_diff, C2_diff = ct_diff

    s = tc.number.random_in_range(1, order)  # nonce

    A1 = int(s) * C1_diff
    A2 = int(s) * C2_diff

    challenge = hash_to_bn(g, dso_ek, C1_1, C1_2, C2_1, C2_2, C1_eq, C2_eq, A1, A2, order=order)

    response = (int(s) + int(challenge) * int(r)) % int(order)

    return (A1, A2, response, challenge)

def verify_r(ct1, ct2, ct_eq, proof, dso_ek):
    """
    Verifies the NIZKP Proof for r
    """
    pp = pub_param()
    g = pp.P
    order = pp.order

    A1, A2, response, challenge = proof

    C1_1, C2_1 = ct1
    C1_2, C2_2 = ct2

    C1_eq, C2_eq = ct_eq

    ct_diff = sub(ct1, ct2)
    C1_diff, C2_diff = ct_diff

    c_check = hash_to_bn(g, dso_ek, C1_1, C1_2, C2_1, C2_2, C1_eq, C2_eq, A1, A2, order=order)

    V1 = int(response) * C1_diff
    V2 = int(response) * C2_diff

    check1 = (V1 == A1 + (int(challenge) * C1_eq))
    check2 = (V2 == A2 + (int(challenge) * C2_eq))

    return check1 and check2 and (int(challenge) == int(c_check))

# Renamed from prove_epet_computation to partial_decrypt
# ({M_share}, π_dec_share) ← PDec_Partial(ct_eq, dk_share)
def partial_decrypt(ct_eq, dk_share):
    """
    Performs partial decryption on a list of ciphertexts using
    this aggregator's secret key share.
    Returns: (M_shares_list, pi_dec_proofs)
    """
    M_shares_list = []
    pi_dec_proofs = []

    for ct_eq_i in ct_eq:
        (C1_i, C2_i) = ct_eq_i
        
        # M_share_i = (C1_i)^dk_share
        M_share_i = int(dk_share) * C1_i
        
        pi_i = "placeholder_proof_of_decryption_share" 
        
        M_shares_list.append(M_share_i)
        pi_dec_proofs.append(pi_i)

    return (M_shares_list, pi_dec_proofs)

def combine_decryption_shares(BB):
    """Combine threshold decryption shares from multiple aggregators."""
    print("Attempting to combine decryption shares...")

    try:
        share_lists = list(BB.M_shares.values())
        if not share_lists:
            print("No decryption shares found on board.")
            return

        num_shares_per_agg = len(share_lists[0])
        ct_eq_list = BB.ct_eq
        
        if len(ct_eq_list) != num_shares_per_agg:
            print("Mismatch between ciphertext count and share count.")
            return

        pp = pub_param()
        g = pp.P
        identity_point = 0 * g
        
        M_set_final = []

        for i in range(len(ct_eq_list)):
            (C1_i, C2_i) = ct_eq_list[i]
            
            # Get share i from each aggregator
            shares_for_ct_i = [share_list[i] for share_list in share_lists]
            
            # Combine shares
            Combined_M_share = shares_for_ct_i[0]
            for j in range(1, len(shares_for_ct_i)):
                Combined_M_share = Combined_M_share + shares_for_ct_i[j]
            
            # Final decryption: C2_i - Combined_M_share
            Plaintext_Point = C2_i + (-Combined_M_share)

            # Check if result is g^0 (identity)
            if Plaintext_Point == identity_point:
                M_set_final.append(1) # "g^0 was found"
            else:
                M_set_final.append(0) # "random number"
        
        BB.M_set = M_set_final
        BB.eval_status = "evaluated_complete"
        print(f"Share combination complete. Final M_set: {BB.M_set}")

    except Exception as e:
        print(f"Error combining shares: {e}")
        BB.eval_status = "evaluation_failed_combination"