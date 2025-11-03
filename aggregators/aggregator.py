# the DSO publishes a signed list of registered aggregators on
# BB. The DSO can update the list of registered smart meters and aggregators dynamically

from xxlimited import foo
import utils.generators as gen
import users.user as user
import dso.DSO as dso
import utils.ec_elgamal as ahe
import utils.dec_proof as dec_proof
import os

NUM_AGG = 4

agg_keys = []
agg_info = {}
agg_names = []
agg_iden = []
dso_ek = None
dso_dk = None

def make_aggregator(pp):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    names_path = os.path.join(base_dir, "../aggregators/names.txt")

    # user names and ids
    with open(names_path, "r") as file:
        for line in file:
            words = line.strip().split()
            ids = [word[0] for word in words if word]
            ids = ids[0] + ". " + ids[1] 
            agg_names.append(line.strip())
            agg_iden.append(ids)

    # aggregator's public keys
    for i in range(NUM_AGG):
        agg_id = agg_iden[i]
        ((id, (pk, pp, proof)), sk) = gen.skey_gen(pp)
        verification = (pk, pp, proof)
        agg_info[agg_id] = verification
    return agg_info

def get_agg_signature(pp):
    return make_aggregator(pp)

r_prime = []
# MIX: create mixed anonymous pk set
# send (pk', πmix) to board
def create_mixed_anon_pk_set(ID_pk):
    global r_prime
    e_prime, r_prime, πmix_proof = gen.mix_id(ID_pk)
    return (e_prime, r_prime, πmix_proof)

# send r' to users
def publish_anon_key():
    return r_prime

def get_report_from_users():
    user_reports = user.generate_and_send_report()
    return user_reports

# This is done so the dk can be used in the Eval function 
def get_encryption_key_set():
    global dso_ek
    global dso_dk

    dso_ek, dso_dk = dso.get_key_set()
    


#=============
# Eval(BB, PBB, dk) → (PBB, BB)
# TODO revise
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
    
    
    # fix
    pub_param = gen.pub_param()
    _, g, order = pub_param
    r = order.random()

    ct_eq = (ct)

    if ct_sum == ct_t_i:
        # need to check if 1 is vaild to use, since g^0 equal 1, but on ec g * 0 equals 0 instead
        return ahe.enc(pub_param, dso_ek, ct_eq)
    else:
        return ahe.e

    return  

def proof_r(ct1, ct2, ct_eq, r):
    """
    generate r proof
    """
    _, g, order = gen.pub_param()

    # extract ciphertexts
    C1_1, C2_1 = ct1
    C1_2, C2_2 = ct2
    C1_eq, C2_eq = ct_eq

    ct_diff = ahe.sub(ct1, ct2)
    C1_diff, C2_diff = ct_diff

    k = order.random() # nonce

    A1 = C1_diff.pt_mul(s)
    A2 = C2_diff.pt_mul(s)

    # Challenge
    challenge = dec_proof.hash_to_bn(g, dso_ek, C1_1, C1_2, C2_1, C2_2, C1_eq, C2_eq, A1, A2, order=order)

    # response
    response = (k + challenge * r) % order

    return (A1, A2, response, challenge)

def verify_r(ct1, ct2, ct_eq, proof):
    """
    Verify NIZK proof that ct_eq = (ct1 / ct2)^r
    Returns b ∈ {0, 1} where b = 1 if proof is valid and 0 otherwise 
    
    Full mathematical verification:
    
    PROVER computed:
    1. ct_diff = ct1 / ct2 = (C1_diff, C2_diff)
    2. ct_eq = ct_diff^r = (C1_diff * r, C2_diff * r) 
    3. A = ct_diff^s = (C1_diff * s, C2_diff * s)
    4. c = Hash(...)
    5. z = s + c*r mod order
    
    VERIFIER checks:
    ct_diff^z ?= A * ct_eq^c
    
    Expanding left side:
    ct_diff^z = ct_diff^(s + c*r)           [substitute z]
            = ct_diff^s * ct_diff^(c*r)     [exponent addition]
            = ct_diff^s * (ct_diff^r)^c     [exponent multiplication]
    
    Expanding right side:
    A * ct_eq^c = ct_diff^s * ct_eq^c       [substitute A]
                = ct_diff^s * (ct_diff^r)^c [substitute ct_eq]
    
    Therefore: ct_diff^z == A * ct_eq^c
    
    This proves the prover knows r such that ct_eq = ct_diff^r
    without revealing r.
    
    For ElGamal ciphertexts ct = (C1, C2):
    ct^k = (C1 * k, C2 * k)  [scalar multiplication on elliptic curve]
    ct1 * ct2 = (C1_1 + C1_2, C2_1 + C2_2)  [point addition]
    """
    _, g, order = gen.pub_param()
    A1, A2, response, challenge = proof

    # extract ciphertexts
    C1_1, C2_1 = ct1
    C1_2, C2_2 = ct2
    C1_eq, C2_eq = ct_eq

    # compute ct_diff
    ct_diff = ahe.sub(ct1, ct2)
    C1_diff, C2_diff = ct_diff

    # Recompute challenge
    challenge_check = dec_proof.hash_to_bn(g, dso_ek, C1_1, C1_2, C2_1, C2_2, C1_eq, C2_eq, A1, A2, order=order)
    # response * ct_diff = A + challenge * ct_eq
    # ct_diff^z == ct_diff^s * ct_diff^(c*r)
    # ct_eq = ct_diff^r

    return ""


# ({M}, π_dec) ← PDec(ct_eq, dk)
def prove_epet_computation(ct_eq, dk):
    """
    Partial decryption with proof.
    For each ct_eq_i ∈ ct_eq: computes g^m_i ← AHE.Dec(dk, ct_eq_i)
    Returns 1 if g^m_i = g^0, encryption of random number otherwise.
    Returns: ({M}, π_dec) where π_dec = {π_i} are zero-knowledge proofs
    """
    return ""
