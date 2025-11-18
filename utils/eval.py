from utils.dec_proof import hash_to_bn
from utils.ec_elgamal import sub, dec, make_table # dec and make_table for debugging
from utils.generators import pub_param
from petlib.ec import EcPt

#=============
# Eval(BB, PBB, dk_share, agg_id, dso_ek) → (PBB, BB)
# with threshold decryption
#=============

# takes dk_share and agg_id instead of full dk
# Takes this aggregator's 'dk_share' and 'agg_id' instead.
def Eval(BB, PBB, dk_share, dso_ek, agg_id):
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
    _, g, order = pub_param()
    identity_point = g.pt_mul(0)
    ct_o = (identity_point, identity_point)

    ord_proof = "ord_proof" # placeholder
    return ct_o, ord_proof

# ctred ← Reduct(ct_b, c_tm, ct_o)
def ct_reduction(ct_b, ct_m, ct_o):
    _, g, order = pub_param()
    identity_point = g.pt_mul(0)
    ct_red = (identity_point, identity_point)
    return ct_red

# ctsum ← Agg(ct_red)
def ct_aggregation(reduc_set):
    C1_prod, C2_prod = reduc_set[0][0]
    for i in range(1, len(reduc_set)):
        C1_i, C2_i = reduc_set[i][0]
        C1_prod = C1_prod.pt_add(C1_i)
        C2_prod = C2_prod.pt_add(C2_i)
    return (C1_prod, C2_prod)

# (cteq, πeq ) ← Pet(ctsum, ctT )
def pet_comparison(ct_sum, ct_T, dso_ek):
    ct_eq = []
    π_eq = []

    for ct_T_i in ct_T:
        ct_eq_i, π_r_i = epet(ct_sum, ct_T_i, dso_ek)
        ct_eq.append(ct_eq_i)
        π_eq.append(π_r_i)

    return (ct_eq, π_eq)

# (ct_eq_i, π_r_i) ← Epet(ct_sum, ct_T_i)
def epet(ct_sum, ct_t_i, dso_ek):
    pp = pub_param()
    _, g, order = pp
    r = order.random()

    ct_diff = sub(ct_sum, ct_t_i)
    (C1_diff, C2_diff) = ct_diff

    C1_eq = C1_diff.pt_mul(r)
    C2_eq = C2_diff.pt_mul(r)
    ct_eq = (C1_eq, C2_eq)

    π_r_i = proof_r(ct_sum, ct_t_i, ct_eq, r, dso_ek)

    return (ct_eq, π_r_i)

def proof_r(ct1, ct2, ct_eq, r, dso_ek):
    _, g, order = pub_param()

    C1_1, C2_1 = ct1
    C1_2, C2_2 = ct2

    C1_eq, C2_eq = ct_eq

    ct_diff = sub(ct1, ct2)
    C1_diff, C2_diff = ct_diff

    s = order.random() # nonce

    A1 = C1_diff.pt_mul(s)
    A2 = C2_diff.pt_mul(s)

    challenge = hash_to_bn(g, dso_ek, C1_1, C1_2, C2_1, C2_2, C1_eq, C2_eq, A1, A2, order=order)

    response = (s + challenge * r) % order

    return (A1, A2, response, challenge)

def verify_r(ct1, ct2, ct_eq, proof, dso_ek):
    _, g, order = pub_param()

    A1, A2, response, challenge = proof

    C1_1, C2_1 = ct1
    C1_2, C2_2 = ct2

    C1_eq, C2_eq = ct_eq

    ct_diff = sub(ct1, ct2)
    C1_diff, C2_diff = ct_diff

    c_check = hash_to_bn(g, dso_ek, C1_1, C1_2, C2_1, C2_2, C1_eq, C2_eq, A1, A2, order=order)

    V1 = C1_diff.pt_mul(response)
    V2 = C2_diff.pt_mul(response)

    check1 = (V1 == A1.pt_add(C1_eq.pt_mul(challenge)))
    check2 = (V2 == A2.pt_add(C2_eq.pt_mul(challenge)))

    return check1 and check2 and (challenge == c_check)

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
    _, g, order = pub_param()

    for ct_eq_i in ct_eq:
        (C1_i, C2_i) = ct_eq_i
        
        # M_share_i = (C1_i)^dk_share
        M_share_i = C1_i.pt_mul(dk_share) 
        
        pi_i = "placeholder_proof_of_decryption_share" 
        
        M_shares_list.append(M_share_i)
        pi_dec_proofs.append(pi_i)

    return (M_shares_list, pi_dec_proofs)

def combine_decryption_shares(BB):
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

        _, g, order = pub_param()
        identity_point = g.pt_mul(0) 
        
        M_set_final = []

        for i in range(len(ct_eq_list)):
            (C1_i, C2_i) = ct_eq_list[i]
            
            # Get share i from each aggregator
            shares_for_ct_i = [share_list[i] for share_list in share_lists]
            
            # Combine shares
            Combined_M_share = shares_for_ct_i[0]
            for j in range(1, len(shares_for_ct_i)):
                Combined_M_share = Combined_M_share.pt_add(shares_for_ct_i[j])
            
            # Final decryption: C2_i - Combined_M_share
            Plaintext_Point = C2_i.pt_add(Combined_M_share.pt_neg())

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

# DEBUGGER
# The dso's dk is purely given here for the debugging, it should not be inserted forproduction
# def combine_decryption_shares(BB, PBB=None, dso_dk=None):
#     """
#     Combines partial decryption shares stored on the Public Board.
#     This is run after a threshold of aggregators have published shares.
#     It computes the final {M} set and posts it to the board.
#     """
#     print("Attempting to combine decryption shares...")

#     try:
#         # Assuming all published shares are needed (t=n)
#         share_lists = list(BB.M_shares.values())
#         if not share_lists:
#             print("No decryption shares found on board.")
#             return

#         # TODO: Add verification of all pi_dec_shares here
        
#         num_shares_per_agg = len(share_lists[0])
#         ct_eq_list = BB.ct_eq
        
#         if len(ct_eq_list) != num_shares_per_agg:
#             print("Mismatch between ciphertext count and share count.")
#             return

#         _, g, order = pub_param()
#         identity_point = g.pt_mul(0) # g^0
        
#         M_set_final = []

#         # ---------- debuggin
#         print("\n--- Debug: Baselines on BB (raw ciphertexts) ---")
#         for i, ct in enumerate(getattr(BB, "ct_T", [])):
#             print(f"  baseline[{i}] = {ct}")

#         if PBB is not None:
#             print("\n--- Debug: Consumption reports on PBB (raw) ---")
#             consumption_reports = getattr(PBB, "ct_t", {})
#             for pk_prime, (t, ct, proof) in consumption_reports.items():
#                 print(f"  pk_prime={pk_prime}, t={t}, ct={ct}")
#         # ---------- end debugging

#         # Go through each ciphertext that was decrypted
#         for i in range(len(ct_eq_list)):
#             (C1_i, C2_i) = ct_eq_list[i]
            
#             # Get share 'i' from each aggregator
#             shares_for_ct_i = [share_list[i] for share_list in share_lists]
            
#             # Combine shares
#             # (C1_i*dk1) + (C1_i*dk2) + ...
#             Combined_M_share = shares_for_ct_i[0]
#             for j in range(1, len(shares_for_ct_i)):
#                 Combined_M_share = Combined_M_share.pt_add(shares_for_ct_i[j])

#             # DEBUG: compute expected combined share from C1_i and full DSO dk (debug only)
#             expected_combined = None
#             if dso_dk is not None:
#                 try:
#                     expected_combined = C1_i.pt_mul(dso_dk)
#                 except Exception as e:
#                     expected_combined = f"expected computation failed: {e}"

#             # Print debug info: per-agg shares, combined, expected, equality
#             print(f"\nDEBUG index {i}:")
#             for idx_ag, share in enumerate(shares_for_ct_i):
#                 print(f"  agg[{idx_ag}] share: {share}")
#             print(f"  Combined_M_share (EcPt): {Combined_M_share}")
#             print(f"  Expected (C1_i * dso.dk): {expected_combined}")
#             print(f"  Combined == Expected? {Combined_M_share == expected_combined}")
            
#             # Final decryption step and remainder of existing debug prints
#             Plaintext_Point = C2_i.pt_add(Combined_M_share.pt_neg())
#             print(f"  Plaintext_Point for index {i}: {Plaintext_Point}")
#             print(f"  Expected identity_point: {identity_point}")

#             # Check if result is g^0 (identity)
#             if Plaintext_Point == identity_point:
#                 M_set_final.append(1) # 1 = "g^0 was found"
#             else:
#                 M_set_final.append(0) # 0 = "random number"
        
#         # ---------- debuggin
#         if dso_dk is not None:
#             try:
#                 expected_combined = C1_i.pt_mul(dso_dk)
#             except Exception as e:
#                 expected_combined = f"expected computation failed: {e}"

#             # Print debug info: per-agg shares, combined, expected
#             print(f"  Shares for index {i}:")
#             for idx_ag, share in enumerate(shares_for_ct_i):
#                 print(f"    agg[{idx_ag}] share: {share}")
#             print(f"  Combined_M_share (EcPt) for index {i}: {Combined_M_share}")
#             if dso_dk is not None:
#                 print(f"  Expected (C1_i * dso.dk): {expected_combined}")

#             print(f"  Plaintext_Point for index {i}: {Plaintext_Point}")
#             print(f"  Expected identity_point: {identity_point}")

#             # If we have dso_dk, also try to decode the Plaintext_Point (sanity)
#             if dso_dk is not None:
#                 try:
#                     pp = BB.pk[1]
#                     table = make_table(pp)
#                     # decode what we computed from the combination
#                     decoded_combination = None
#                     try:
#                         decoded_combination = dec(dso_dk, pp, table, (C1_i, C2_i))
#                     except Exception:
#                         decoded_combination = "<could not decode (C1_i,C2_i)>"
#                     print(f"  dec( dso.dk, ct_eq[{i}] )  => (DEBUG) should match computed plain: {decoded_combination}")
#                 except Exception:
#                     pass
#         if dso_dk is not None:
#             try:
#                 pp = BB.pk[1]
#                 table = make_table(pp)
#                 print("\n--- Decoded baselines (using DSO dk) ---")
#                 for i, ct in enumerate(getattr(BB, "ct_T", [])):
#                     plain = dec(dso_dk, pp, table, ct)
#                     if plain in table:
#                         print(f"  baseline[{i}] -> {table[plain]}")
#                     else:
#                         print(f"  baseline[{i}] -> {plain}")

#                 if PBB is not None:
#                     print("\n--- Decoded consumption reports (using DSO dk) ---")
#                     for pk_prime, (t, ct_obj, proof) in consumption_reports.items():
#                         if isinstance(ct_obj, (list, tuple)):
#                             bits = []
#                             for c in ct_obj:
#                                 p = dec(dso_dk, pp, table, c)
#                                 bits.append(table[p] if p in table else p)
#                             print(f"  pk_prime={pk_prime} -> {bits}")
#                         else:
#                             plain = dec(dso_dk, pp, table, ct_obj)
#                             print(f"  pk_prime={pk_prime} -> {table[plain] if plain in table else plain}")
#             except Exception as e:
#                 print(f"Decoding with DSO key failed: {e}")
#         # ---------- end debugging

#         # Publish final results to the board
#         BB.M_set = M_set_final
#         BB.eval_status = "evaluated_complete"
#         print(f"Share combination complete. Final M_set: {BB.M_set}")

#     except Exception as e:
#         print(f"Error combining shares: {e}")
#         BB.eval_status = "evaluation_failed_combination"

# clean version without debug, dk, and pbb



# #=============
# # Eval(BB, PBB, dk) → (PBB, BB)
# # TODO revise (not finished)
# # TODO needs to be reworked for threshold partial decryption
# #=============

# def Eval(BB, PBB, dk, dso_ek):
#     # list of cts
#     # ct_b: baseline ciphertexts from BB
#     ct_b = getattr(BB, "ct_b", None)
#     if ct_b is None:
#         print("Public board missing baseline ciphertexts (ct_b).")
#         return (PBB, BB)

#     # ct_t: consumption reports from PBB
#     consumption_reports = getattr(PBB, "ct_t", None)
#     if consumption_reports is None:
#         print("Private board missing consumption reports (ct_t).")
#         return (PBB, BB)

#     # print("len of ct_b: " + str(len(ct_b)))
#     # print("len of consumption_reports: " + str(len(consumption_reports)))

#     try:
#         ct_T = BB.ct_T
#     except AttributeError:
#         print("No ct_T found in BB during Eval")
#         return (PBB, BB)
    
#     # lists
#     eval_results_step1 = [] # for (ct_o, t, pk_prime, ord_proof)
#     CT_red = [] # for {(ct_red, t, pk_prime)}

#     for pk_prime, report_data in consumption_reports.items():
#         t = report_data[0]
#         ct_m = report_data[1] # ct_m is the encrypted energy consumption (ct_t) of a specific anonymous user (pk_prime)

#         # step 1:ord comparison
#         ct_o, ord_proof = ord_comparison(ct_b, ct_m)

#         # ct_o is encryption of 1 if consumption < baseline (reduction is achieved)
#         # ct_o is encryption of 0 otherwise

#         # store results for BB
#         eval_results_step1.append((ct_o, t, pk_prime, ord_proof))

#         # step 2 ct reduction
#         ct_red = ct_reduction(ct_b, ct_m, ct_o) # just placeholders

#         # step 3 set CT_red
#         CT_red.append((ct_red, t, pk_prime))

#     # step 4
#     # ct_sum <- Agg(ct_red)
#     ct_sum = ct_aggregation(CT_red)

#     # step 5
#     # (ct_eq, πeq) <- Pet(ct_sum, ct_T)
#     ct_eq, π_eq = pet_comparison(ct_sum, ct_T, dso_ek)

#     # step 6
#     M_set, π_dec = prove_epet_computation(ct_eq, dk)
    
#     #####
#     # Update the boards with eval results
#     # Public board
#     BB.eval_results = eval_results_step1 
#     BB.eval_status = "evaluated"
#     BB.ct_eq = ct_eq
#     BB.π_eq = π_eq
#     BB.M_set = M_set
#     BB.π_dec = π_dec

#     # private board
#     PBB.eval_data = {
#         "ct_b": ct_b,
#         "consumption_reports": consumption_reports,
#         "dk": dk
#     }
    
#     return (PBB, BB)

# # (cto, t, pk′, πord) ← ord(ctb, ctm)
# def ord_comparison(ct_b, ct_m):
#     """
#     Order comparison of two ciphertexts in binary form.
#     Returns: (ct_o, π_ord)
#     ct_o is encryption of 1 if m < b, 0 otherwise
#     """
#     _, g, order = pub_param()
#     identity_point = g.pt_mul(0)
    
#     ct_o = (identity_point, identity_point)
#     ord_proof = "ord_proof"
#     return ct_o, ord_proof

# # ctred ← Reduct(ct_b, c_tm, ct_o)
# def ct_reduction(ct_b, ct_m, ct_o):
#     """
#     Computes encryption of subtraction ct_red ← Diff(ct_b, ct_m) if ct_o is encryption of 1.
#     Returns: ct_red
#     """
#     _, g, order = pub_param()
#     identity_point = g.pt_mul(0)
    
#     ct_red = (identity_point, identity_point)
#     return ct_red

# # step 4
# # ctsum ← Agg(ct_red)
# def ct_aggregation(reduc_set):
#     """
#     Aggregates ciphertexts: ct = ∏(ct_i ∈ CT_red)^ct_i
#     Transforms to ciphertext ct_sum containing integer plaintext.
#     Returns: ct_sum
#     """
#     # reduc_set[0] is a tuple (ct_red, t, pk′)
#     C1_prod, C2_prod = reduc_set[0][0]

#     for i in range(1, len(reduc_set)):
#         C1_i, C2_i = reduc_set[i][0]

#         C1_prod = C1_prod.pt_add(C1_i)
#         C2_prod = C2_prod.pt_add(C2_i)

#     return (C1_prod, C2_prod)

# # (cteq, πeq ) ← Pet(ctsum, ctT )
# def pet_comparison(ct_sum, ct_T, dso_ek):
#     """
#     Private equality test.
#     Computes (ct_eq_i, π_r_i) ← Epet(ct_sum, ct_T_i) for each ct_T_i ∈ ct_T.
#     ct_eq_i is encryption of g^0 if sum = t_i, random number otherwise.
#     Returns: (ct_eq, π_eq) where π_eq = {π_r_i}, ct_eq = {ct_eq_i}
#     """
#     ct_eq = []
#     π_eq = []

#     for ct_T_i in ct_T:
#         ct_eq_i, π_r_i = epet(ct_sum, ct_T_i, dso_ek)
#         ct_eq.append(ct_eq_i)
#         π_eq.append(π_r_i)
        
#     return (ct_eq, π_eq)

# # (ct_eq_i, π_r_i) ← Epet(ct_sum, ct_T_i)
# def epet(ct_sum, ct_t_i, dso_ek):
#     """
#     Single equality test computation.
#     Returns: (ct_eq_i, π_r_i)
#     ct_eq_i is encryption of g^0 if sum = t_i, random number otherwise.
#     π_r_i is the zero knowledge proof
#     """
    
#     pp = pub_param()
#     _, g, order = pp
#     r = order.random()

#     # ct_eq = ct_diff^r
#     # ct_diff = ct_sum - ct_t_i
#     ct_diff = sub(ct_sum, ct_t_i)
#     (C1_diff, C2_diff) = ct_diff

#     C1_eq = C1_diff.pt_mul(r)
#     C2_eq = C2_diff.pt_mul(r)
#     ct_eq = (C1_eq, C2_eq)

#     π_r_i = proof_r(ct_sum, ct_t_i, ct_eq, r, dso_ek)

#     return (ct_eq, π_r_i)

# def proof_r(ct1, ct2, ct_eq, r, dso_ek):
#     """
#     generate r proof
#     """
#     _, g, order = pub_param()

#     # extract ciphertexts
#     C1_1, C2_1 = ct1
#     C1_2, C2_2 = ct2
#     C1_eq, C2_eq = ct_eq

#     ct_diff = sub(ct1, ct2)
#     C1_diff, C2_diff = ct_diff

#     # 
#     s = order.random() # nonce

#     A1 = C1_diff.pt_mul(s)
#     A2 = C2_diff.pt_mul(s)

#     # Challenge
#     challenge = hash_to_bn(g, dso_ek, C1_1, C1_2, C2_1, C2_2, C1_eq, C2_eq, A1, A2, order=order)

#     # response
#     response = (s + challenge * r) % order

#     return (A1, A2, response, challenge)

# def verify_r(ct1, ct2, ct_eq, proof, dso_ek):
#     """
#     Verify NIZK proof that ct_eq = (ct1 / ct2)^r
#     Returns b ∈ {0, 1} where b = 1 if proof is valid and 0 otherwise

#     Prover:
#     A1 = C1_diff * s (commitment 1)
#     A2 = C2_diff * s (commitment 2)
#     response = (s + challenge * r) % order
#     challenge = hashing...
    
#     verifier:
#     THe verifier wants to check that
#     ct_diff * response == A + ct_eq * challenge
#     so:

#     LEFT SIDE                 RIGHT SIDE

#     C1_diff * response    ==  A1 + (C1_eq * challenge)
#     C2_diff * response    ==  A2 + (C2_eq * challenge)

#     check 1:
#     left side:
#     V1  = C1_diff.pt_mul(response)
#         = C1_diff * response
#         = C1_diff * (s * challenge * r)
#         = C1_diff * s + C1_diff * (challenge * r)
#         = C1_diff * s + C1_diff * r * challenge
#         = C1_diff * s (C1_diff * r) * challenge

#     right side:
#     A1 + C1_eq.pt_mul(challenge)
#         = A1 + (C1_eq * challenge)
#         = (C1_diff * s) + (C1_eq * challenge)
#         = (C1_diff * s) + (C1_diff * r) * challenge
#         = C1_diff * s + C1_diff * r * challenge
    
#     check 1 shows V1 == A1 + C1_eq * challenge

#     check 2:
#     left side
#     V2  = C2_diff.pt_mul(response)
#         = C2_diff * response
#         = C2_diff * (s * challenge * r)
#         = C2_diff * s + C2_diff * (challenge * r)
#         = C2_diff * s + C2_diff * r * challenge
#         = C2_diff * s (C2_diff * r) * challenge
    
#     right side:
#     A2.pt_add(C2_eq.pt_mul(challenge))
#         = A2 + (C2_eq * challenge)
#         = (C2_diff * s) + (C2_eq * challenge)
#         = (C2_diff * s) + (C2_diff * r) * challenge
#         = C2_diff * s + C2_diff * r * challenge
    
#     check 2 shows V2 == A2 + C2_eq * challenge
#     """

#     _, g, order = pub_param()
#     A1, A2, response, challenge = proof

#     # extract ciphertexts
#     C1_1, C2_1 = ct1
#     C1_2, C2_2 = ct2
#     C1_eq, C2_eq = ct_eq

#     # compute ct_diff
#     ct_diff = sub(ct1, ct2)
#     C1_diff, C2_diff = ct_diff

#     # Recompute challenge
#     c_check = hash_to_bn(g, dso_ek, C1_1, C1_2, C2_1, C2_2, C1_eq, C2_eq, A1, A2, order=order)
#     # response * ct_diff = A + challenge * ct_eq
#     # ct_diff^z == ct_diff^s * ct_diff^(c*r)
#     # ct_eq = ct_diff^r

#     # Commitments: A = ct_diff^s
#     V1 = C1_diff.pt_mul(response)
#     V2 = C2_diff.pt_mul(response)
    
#     check1 = (V1 == A1.pt_add(C1_eq.pt_mul(challenge)))
#     check2 = (V2 == A2.pt_add(C2_eq.pt_mul(challenge)))
    
#     return check1 and check2 and (challenge == c_check)

# # TODO needs to be reworked for threshold partial decryption
# # ({M}, π_dec) ← PDec(ct_eq, dk)
# def prove_epet_computation(ct_eq, dk):
#     """
#     Partial decryption with proof.
#     For each ct_eq_i ∈ ct_eq: computes g^m_i ← AHE.Dec(dk, ct_eq_i)
#     Returns 1 if g^m_i = g^0, encryption of random number otherwise.
#     Returns: ({M}, π_dec) where π_dec = {π_i} are zero-knowledge proofs
#     """
#     M_set = [{"M_i": 1 }]
#     π_dec = [{"π_i": "proof"}]

#     return (M_set, π_dec)
