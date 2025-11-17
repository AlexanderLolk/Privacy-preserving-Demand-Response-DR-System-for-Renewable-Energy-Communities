from utils.dec_proof import hash_to_bn
from utils.ec_elgamal import sub
from utils.generators import pub_param
from petlib.ec import EcPt

#=============
# Eval(BB, PBB, dk) → (PBB, BB)
# TODO revise (not finished)
#=============

def Eval(BB, PBB, dk, dso_ek):
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

    # print("len of ct_b: " + str(len(ct_b)))
    # print("len of consumption_reports: " + str(len(consumption_reports)))

    try:
        ct_T = BB.ct_T
    except AttributeError:
        print("No ct_T found in BB during Eval")
        return (PBB, BB)
    
    # lists
    eval_results_step1 = [] # for (ct_o, t, pk_prime, ord_proof)
    CT_red = [] # for {(ct_red, t, pk_prime)}

    for pk_prime, report_data in consumption_reports.items():
        t = report_data[0]
        ct_m = report_data[1] # ct_m is the encrypted energy consumption (ct_t) of a specific anonymous user (pk_prime)

        # step 1:ord comparison
        ct_o, ord_proof = ord_comparison(ct_b, ct_m)

        # ct_o is encryption of 1 if consumption < baseline (reduction is achieved)
        # ct_o is encryption of 0 otherwise

        # store results for BB
        eval_results_step1.append((ct_o, t, pk_prime, ord_proof))

        # step 2 ct reduction
        ct_red = ct_reduction(ct_b, ct_m, ct_o) # just placeholders

        # step 3 set CT_red
        CT_red.append((ct_red, t, pk_prime))

    # step 4
    # ct_sum <- Agg(ct_red)
    ct_sum = ct_aggregation(CT_red)

    # step 5
    # (ct_eq, πeq) <- Pet(ct_sum, ct_T)
    ct_eq, π_eq = pet_comparison(ct_sum, ct_T, dso_ek)

    # step 6
    M_set, π_dec = prove_epet_computation(ct_eq, dk)
    
    #####
    # Update the boards with eval results
    # Public board
    BB.eval_results = eval_results_step1 
    BB.eval_status = "evaluated"
    BB.ct_eq = ct_eq
    BB.π_eq = π_eq
    BB.M_set = M_set
    BB.π_dec = π_dec

    # private board
    PBB.eval_data = {
        "ct_b": ct_b,
        "consumption_reports": consumption_reports,
        "dk": dk
    }
    
    return (PBB, BB)

# (cto, t, pk′, πord) ← ord(ctb, ctm)
def ord_comparison(ct_b, ct_m):
    """
    Order comparison of two ciphertexts in binary form.
    Returns: (ct_o, π_ord)
    ct_o is encryption of 1 if m < b, 0 otherwise
    """
    _, g, order = pub_param()
    identity_point = g.pt_mul(0)
    
    ct_o = (identity_point, identity_point)
    ord_proof = "ord_proof"
    return ct_o, ord_proof

# ctred ← Reduct(ct_b, c_tm, ct_o)
def ct_reduction(ct_b, ct_m, ct_o):
    """
    Computes encryption of subtraction ct_red ← Diff(ct_b, ct_m) if ct_o is encryption of 1.
    Returns: ct_red
    """
    _, g, order = pub_param()
    identity_point = g.pt_mul(0)
    
    ct_red = (identity_point, identity_point)
    return ct_red

# step 4
# ctsum ← Agg(ct_red)
def ct_aggregation(reduc_set):
    """
    Aggregates ciphertexts: ct = ∏(ct_i ∈ CT_red)^ct_i
    Transforms to ciphertext ct_sum containing integer plaintext.
    Returns: ct_sum
    """
    # reduc_set[0] is a tuple (ct_red, t, pk′)
    C1_prod, C2_prod = reduc_set[0][0]

    for i in range(1, len(reduc_set)):
        C1_i, C2_i = reduc_set[i][0]

        C1_prod = C1_prod.pt_add(C1_i)
        C2_prod = C2_prod.pt_add(C2_i)

    return (C1_prod, C2_prod)

# (cteq, πeq ) ← Pet(ctsum, ctT )
def pet_comparison(ct_sum, ct_T, dso_ek):
    """
    Private equality test.
    Computes (ct_eq_i, π_r_i) ← Epet(ct_sum, ct_T_i) for each ct_T_i ∈ ct_T.
    ct_eq_i is encryption of g^0 if sum = t_i, random number otherwise.
    Returns: (ct_eq, π_eq) where π_eq = {π_r_i}, ct_eq = {ct_eq_i}
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
    Single equality test computation.
    Returns: (ct_eq_i, π_r_i)
    ct_eq_i is encryption of g^0 if sum = t_i, random number otherwise.
    π_r_i is the zero knowledge proof
    """
    
    pp = pub_param()
    _, g, order = pp
    r = order.random()

    # ct_eq = ct_diff^r
    # ct_diff = ct_sum - ct_t_i
    ct_diff = sub(ct_sum, ct_t_i)
    (C1_diff, C2_diff) = ct_diff

    C1_eq = C1_diff.pt_mul(r)
    C2_eq = C2_diff.pt_mul(r)
    ct_eq = (C1_eq, C2_eq)

    π_r_i = proof_r(ct_sum, ct_t_i, ct_eq, r, dso_ek)

    return (ct_eq, π_r_i)

def proof_r(ct1, ct2, ct_eq, r, dso_ek):
    """
    generate r proof
    """
    _, g, order = pub_param()

    # extract ciphertexts
    C1_1, C2_1 = ct1
    C1_2, C2_2 = ct2
    C1_eq, C2_eq = ct_eq

    ct_diff = sub(ct1, ct2)
    C1_diff, C2_diff = ct_diff

    s = order.random() # nonce

    A1 = C1_diff.pt_mul(s)
    A2 = C2_diff.pt_mul(s)

    # Challenge
    challenge = hash_to_bn(g, dso_ek, C1_1, C1_2, C2_1, C2_2, C1_eq, C2_eq, A1, A2, order=order)

    # response
    # TODO figure out r 
    response = (s + challenge * r) % order

    return (A1, A2, response, challenge)

def verify_r(ct1, ct2, ct_eq, proof, dso_ek):
    """
    Verify NIZK proof that ct_eq = (ct1 / ct2)^r
    Returns b ∈ {0, 1} where b = 1 if proof is valid and 0 otherwise

    Prover:
    A1 = C1_diff * s (commitment 1)
    A2 = C2_diff * s (commitment 2)
    response = (s + challenge * r) % order
    challenge = hashing...
    
    verifier:
    THe verifier wants to check that
    ct_diff * response == A + ct_eq * challenge
    so:

    LEFT SIDE                 RIGHT SIDE

    C1_diff * response    ==  A1 + (C1_eq * challenge)
    C2_diff * response    ==  A2 + (C2_eq * challenge)

    check 1:
    left side:
    V1  = C1_diff.pt_mul(response)
        = C1_diff * response
        = C1_diff * (s * challenge * r)
        = C1_diff * s + C1_diff * (challenge * r)
        = C1_diff * s + C1_diff * r * challenge
        = C1_diff * s (C1_diff * r) * challenge

    right side:
    A1 + C1_eq.pt_mul(challenge)
        = A1 + (C1_eq * challenge)
        = (C1_diff * s) + (C1_eq * challenge)
        = (C1_diff * s) + (C1_diff * r) * challenge
        = C1_diff * s + C1_diff * r * challenge
    
    check 1 shows V1 == A1 + C1_eq * challenge

    check 2:
    left side
    V2  = C2_diff.pt_mul(response)
        = C2_diff * response
        = C2_diff * (s * challenge * r)
        = C2_diff * s + C2_diff * (challenge * r)
        = C2_diff * s + C2_diff * r * challenge
        = C2_diff * s (C2_diff * r) * challenge
    
    right side:
    A2.pt_add(C2_eq.pt_mul(challenge))
        = A2 + (C2_eq * challenge)
        = (C2_diff * s) + (C2_eq * challenge)
        = (C2_diff * s) + (C2_diff * r) * challenge
        = C2_diff * s + C2_diff * r * challenge
    
    check 2 shows V2 == A2 + C2_eq * challenge
    """

    _, g, order = pub_param()
    A1, A2, response, challenge = proof

    # extract ciphertexts
    C1_1, C2_1 = ct1
    C1_2, C2_2 = ct2
    C1_eq, C2_eq = ct_eq

    # compute ct_diff
    ct_diff = sub(ct1, ct2)
    C1_diff, C2_diff = ct_diff

    # Recompute challenge
    c_check = hash_to_bn(g, dso_ek, C1_1, C1_2, C2_1, C2_2, C1_eq, C2_eq, A1, A2, order=order)
    # response * ct_diff = A + challenge * ct_eq
    # ct_diff^z == ct_diff^s * ct_diff^(c*r)
    # ct_eq = ct_diff^r

    # Commitments: A = ct_diff^s
    V1 = C1_diff.pt_mul(response)
    V2 = C2_diff.pt_mul(response)
    
    check1 = (V1 == A1.pt_add(C1_eq.pt_mul(challenge)))
    check2 = (V2 == A2.pt_add(C2_eq.pt_mul(challenge)))
    
    return check1 and check2 and (challenge == c_check)

# ({M}, π_dec) ← PDec(ct_eq, dk)
def prove_epet_computation(ct_eq, dk):
    """
    Partial decryption with proof.
    For each ct_eq_i ∈ ct_eq: computes g^m_i ← AHE.Dec(dk, ct_eq_i)
    Returns 1 if g^m_i = g^0, encryption of random number otherwise.
    Returns: ({M}, π_dec) where π_dec = {π_i} are zero-knowledge proofs
    """
    M_set = [{"M_i": 1 }]
    π_dec = [{"π_i": "proof"}]

    return (M_set, π_dec)
