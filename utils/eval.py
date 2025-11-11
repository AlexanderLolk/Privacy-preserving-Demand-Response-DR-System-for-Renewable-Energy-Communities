from utils.dec_proof import hash_to_bn
from utils.ec_elgamal import enc, sub
from utils.generators import pub_param 

#=============
# Eval(BB, PBB, dk) → (PBB, BB)
# TODO revise (not finished)
#=============

def Eval(BB, PBB, dk):
    # list of cts
    ct_b = BB.ct_b
    consumption_reports = PBB.ct_t # {pk': (t, ct_c, σ)}

    # print("len of ct_b: " + str(len(ct_b)))
    # print("len of consumption_reports: " + str(len(consumption_reports)))

    eval_results = []

    t = []
    pk_prime_list = []

    for pk_prime, report_data in consumption_reports.items():
        t = report_data[0]
        ct_c = report_data[1]

        # step 1:ord comparison
        ct_o, ord_proof = ord_comparison(ct_b, ct_c, dk)

        # ct_o is encryption of 1 if consumption < baseline (reduction is achieved)
        # ct_o is encryption of 0 otherwise

        result = (ct_o, t, pk_prime, ord_proof)
        eval_results.append(result)
    
    # step 2
    reduc_set = []
    for i in range(len(ct_b)):
        ct_i = ct_b[i]
        consumption_reports_i = consumption_reports[i]
        ct_0 = "fix"
        
        # diff not right
        pk_prime = pk_prime_list[i]
        time_stamp = t[i]

        ct_red = ct_reduction(ct_i, consumption_reports_i, ct_0)

        #step 3
        reduc_set.append((ct_red, time_stamp, pk_prime))


    # step 4
    ct_sum = ct_aggregation(reduc_set)


    # step 5
    # step 6
    

    # public board

    BB.eval_results = eval_results
    BB.eval_status = "evaluated"

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
    return ""

# whtat is ct_m
# ctred ← Reduct(ct_b, c_tm, ct_o)
def ct_reduction(ct_b, ct_m, ct_o):
    """
    Computes encryption of subtraction ct_red ← Diff(ct_b, ct_m) if ct_o is encryption of 1.
    Returns: ct_red
    """
    return ""

# CT_red = {(ct_red, t, pk′)}
def build_reduction_set(eval_results):
    """
    Builds set CT_red = {(ct_red, t, pk′)} for all pk′ ∈ pk′.
    Returns: CT_red
    """
    return ""

# step 4
# ctsum ← Agg(ct_red)
def ct_aggregation(reduc_set):
    """
    Aggregates ciphertexts: ct = ∏(ct_i ∈ CT_red)^ct_i
    Transforms to ciphertext ct_sum containing integer plaintext.
    Returns: ct_sum
    """
    ct_red = 0
    prev = reduc_set[0]
    for i in range(1, len(reduc_set)):
        
        ct_red = reduc_set[i][0] * prev
        prev = ct_red

    return str(ct_red)

# (cteq, πeq ) ← Pet(ctsum, ctT )
def pet_comparison(ct_sum, ct_T):
    """
    Private equality test.
    Computes (ct_eq_i, π_r_i) ← Epet(ct_sum, ct_T_i) for each ct_T_i ∈ ct_T.
    ct_eq_i is encryption of g^0 if sum = t_i, random number otherwise.
    Returns: (ct_eq, π_eq) where π_eq = {π_r_i}, ct_eq = {ct_eq_i}
    """
    ct_eq = []
    π_eq = []

    for ct_T_i in ct_T:
        ct_eq_i, π_r_i = epet(ct_sum, ct_T_i)
        ct_eq.append(ct_eq_i)
        π_eq.append(π_r_i)
        
    return (ct_eq, π_eq)

# (ct_eq_i, π_r_i) ← Epet(ct_sum, ct_T_i)
def epet(ct_sum, ct_t_i):
    """
    Single equality test computation.
    Returns: (ct_eq_i, π_r_i)
    ct_eq_i is encryption of g^0 if sum = t_i, random number otherwise.
    π_r_i is the zero knowledge proof
    """
    
    # fix fix fix
    pub_param = pub_param()
    _, g, order = pub_param
    r = order.random()

    # ct_eq = ct_diff^r
    # ct_diff = ct_sum - ct_t_i
    ct_eq = (ct)

    if ct_sum == ct_t_i:
        # need to check if 1 is vaild to use, since g^0 equal 1, but on ec g * 0 equals 0 instead
        return enc(pub_param, dso_ek, ct_eq)
    else:
        return enc(pub_param, dso_ek, r)

    pass

def proof_r(ct1, ct2, ct_eq, r):
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

def verify_r(ct1, ct2, ct_eq, proof):
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
    return ""
