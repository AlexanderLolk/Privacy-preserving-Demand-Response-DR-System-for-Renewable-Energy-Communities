# # Reading material at voting17_HLKD17.pdf
import hashlib
import random
import utils.generators as gen
import threshold_crypto as tc

# main
def get_h_generators(N):
    """ """
    pp = gen.pp
    g = pp.P
    order = pp.order
    h_generators_local = []
    
    for i in range(N):
        # Use random scalar
        h_scalar = tc.number.random_in_range(1, order)
        h_i_point = int(h_scalar) * g
        h_generators_local.append(h_i_point)
    
    return h_generators_local

# Generates a random permutation ψ ∈ Ψ_N
def GenPermutation(N):
    """ """
    I = list(range(N))
    j_i = list(range(N))
    for i in range(N):
        k = random.randint(i, N-1)
        j_i[i] = I[k]
        I[k] = I[i]
    return j_i

def GenShuffle(e):
    """ """
    N = len(e)
    ψ = GenPermutation(N)
    pp = gen.pp
    g = pp.P
    order = pp.order
    
    r_prime = []
    e_prime = []

    for i in range(N):
        r_i = tc.number.random_in_range(1, order)
        r_prime.append(r_i)

        # Additive blinding e[i] + r_i * G
        blinding_factor = int(r_i) * g
        pk_prime = e[i] + blinding_factor

        e_prime.append(pk_prime)

    # shuffle it
    e_prime_shuffled = [e_prime[ψ[j]] for j in range(N)]
    return (e_prime_shuffled, r_prime, ψ)

# GenCommitment() generates a commitment c = Com(ψ, r) to a permutation ψ by
# committing to the columns of the corresponding permutation matrix.
def GenCommitment(ψ, h_gens):
    """ 
    Commits to the permutation matrix.
    """
    pp = gen.pp
    g = pp.P
    order = pp.order

    N = len(ψ)
    
    # Pre-allocate list
    c = [None] * N 
    r = []

    # Generate randomness for all N commitments
    for _ in range(N):
        r.append(tc.number.random_in_range(1, order))

    for i in range(N):
        j = ψ[i]
        
        # c[j] = r[j] * G + h_gens[i]
        h_term = h_gens[i]
        g_term = int(r[j]) * g
        c[j] = h_term + g_term

    return (c, r)

def GenCommitmentChain(c0, u):
    """ """
    pp = gen.pp
    g = pp.P
    order = pp.order
    N = len(u)
    c = []
    r = []

    for i in range(N):
        r_i = tc.number.random_in_range(1, order)
        r.append(r_i)
        
        if i == 0:
            prev_c = c0
        else:
            prev_c = c[i - 1]
         
        # c_i = r_i * g + u_i * c_{i-1}
        c_i = (int(r_i) * g) + (int(u[i]) * prev_c)
        c.append(c_i)

        prev_c = c_i
    
    return (c, r)

def hash_to_zq(data):
    """ """
    hasher = hashlib.sha256()
    hasher.update(str(data).encode())
    digest = hasher.digest()
    return int.from_bytes(digest, "big")

# pk for ours is ek
def GenProof(e, e_prime, r_prime, ψ, pk):
    """ """
    pp = gen.pp
    g = pp.P
    order = pp.order

    N = len(e)
    q = int(order)

    # get h
    h_gens = get_h_generators(N)

    # Step 1: Commit to permutation
    c, r = GenCommitment(ψ, h_gens)

    # Step 2-7: Generate challenges
    u = []
    for i in range(N):
        u_i = hash_to_zq((str(e), str(e_prime), str(c), i))
        u.append(u_i)

    u_prime = [u[ψ[j]] for j in range(N)]
        
    # GenCommitmentChain
    h_scalar = tc.number.random_in_range(1, order)
    h = int(h_scalar) * g
    c_hat, r_hat = GenCommitmentChain(h, u_prime)

    # Step 8-14: Compute weighted sums
    r_bar = sum(int(r_val) for r_val in r) % q

    v = [0] * N
    v[N-1] = 1
    for i in range(N-2, -1, -1):
        v[i] = (int(u_prime[i+1]) * v[i+1]) % q
    
    r_hat_sum = sum((int(r_hat[i]) * v[i]) % q for i in range(N)) % q
    r_tilde = sum((int(r[i]) * int(u[i])) % q for i in range(N)) % q
    r_prime_sum = sum((int(r_prime[i]) * int(u[i])) % q for i in range(N)) % q

    # Step 15-25: Generate witnesses
    w = [tc.number.random_in_range(1, order) for _ in range(4)]
    w_hat = [tc.number.random_in_range(1, order) for _ in range(N)]
    w_prime = [tc.number.random_in_range(1, order) for _ in range(N)]

    # t-values (commitments)
    t1 = int(w[0]) * g
    t2 = int(w[1]) * g
    t3 = int(w[2]) * g
    for i in range(N):
        t3 = t3 + (int(w_prime[i]) * h_gens[i])
    
    # t4 = Σ(w'_i * e'_i) - w[3] * G
    sum_w_prime_e_prime = int(w_prime[0]) * e_prime[0]
    for i in range(1, N):
        sum_w_prime_e_prime = sum_w_prime_e_prime + (int(w_prime[i]) * e_prime[i])
    
    w3_g = int(w[3]) * g
    t4 = sum_w_prime_e_prime + (-w3_g)

    t_hat = []
    for i in range(N):
        if i == 0:
            prev_c = h
        else:
            prev_c = c_hat[i-1]
        
        hat_t_i = (int(w_hat[i]) * g) + (int(w_prime[i]) * prev_c)
        t_hat.append(hat_t_i)
    
    # Step 26-27: Compute challenge
    y = (str(e), str(e_prime), str(c), str(c_hat), str(pk))
    t = (str(t1), str(t2), str(t3), str(t4), str(t_hat))
    challenge = hash_to_zq((y, t))

    # Step 28-33: Compute responses
    s1 = (int(w[0]) + int(challenge) * r_bar) % q
    s2 = (int(w[1]) + int(challenge) * r_hat_sum) % q
    s3 = (int(w[2]) + int(challenge) * r_tilde) % q
    s4 = (int(w[3]) + int(challenge) * r_prime_sum) % q

    s_hat = [(int(w_hat[i]) + int(challenge) * int(r_hat[i])) % q for i in range(N)]
    s_prime = [(int(w_prime[i]) + int(challenge) * int(u_prime[i])) % q for i in range(N)]

    proof = {
        't': (t1, t2, t3, t4, t_hat),
        's': (s1, s2, s3, s4, s_hat, s_prime),
        'c': c,
        'c_hat': c_hat,
        'h': h,
        'h_gens': h_gens,
    }

    return proof

def verify_shuffle_proof(proof, e, e_prime, pk):
    """ """
    pp = gen.pp
    g = pp.P
    order = pp.order
    N = len(e)
    
    # Extract proof components
    t1, t2, t3, t4, t_hat = proof["t"]
    s1, s2, s3, s4, s_hat, s_prime = proof["s"]
    c = proof["c"]
    c_hat = proof["c_hat"]
    h = proof["h"]
    h_gens = proof["h_gens"]
    
    # Recompute challenges u
    u = []
    for i in range(N):
        u_i = hash_to_zq((str(e), str(e_prime), str(c), i))
        u.append(u_i)
    
    # c_bar = Σc_i - Σh_i
    c_bar = c[0]
    for i in range(1, N):
        c_bar = c_bar + c[i]
    
    h_sum = h_gens[0]
    for i in range(1, N):
        h_sum = h_sum + h_gens[i]
    
    c_bar = c_bar + (-h_sum)
    
    # u_product = ∏u_i
    u_product = 1
    for i in range(N):
        u_product = (u_product * int(u[i])) % int(order)
    
    # c_hat_final = c_hat[N-1] - u_product * h
    c_hat_final = c_hat[N-1] + (-(int(u_product) * h))
    
    # c_tilde = Σ(u_i * c_i)
    c_tilde = int(u[0]) * c[0]
    for i in range(1, N):
        c_tilde = c_tilde + (int(u[i]) * c[i])
    
    # Recompute challenge
    y = (str(e), str(e_prime), str(c), str(c_hat), str(pk))
    t = (str(t1), str(t2), str(t3), str(t4), str(t_hat))
    challenge = hash_to_zq((y, t))
    
    # Verify t1 = -challenge*c_bar + s1*g
    t1_prime = (-(int(challenge) * c_bar)) + (int(s1) * g)
    t1_check = (t1 == t1_prime)
    
    # Verify t2 = -challenge*c_hat_final + s2*g
    t2_prime = (-(int(challenge) * c_hat_final)) + (int(s2) * g)
    t2_check = (t2 == t2_prime)
    
    # Verify t3
    t3_prime_1 = -(int(challenge) * c_tilde)
    t3_prime_2 = int(s3) * g
    t3_prime_prod = int(s_prime[0]) * h_gens[0]
    
    for i in range(1, N):
        t3_prime_prod = t3_prime_prod + (int(s_prime[i]) * h_gens[i])
    
    t3_prime = t3_prime_1 + t3_prime_2 + t3_prime_prod
    t3_check = (t3 == t3_prime)

    # Verify t4
    sum_s_prime_e_prime = int(s_prime[0]) * e_prime[0]
    for i in range(1, N):
        sum_s_prime_e_prime = sum_s_prime_e_prime + (int(s_prime[i]) * e_prime[i])
    
    sum_u_e = int(u[0]) * e[0]
    for i in range(1, N):
        sum_u_e = sum_u_e + (int(u[i]) * e[i])

    term_challenge = int(challenge) * sum_u_e
    term_s4 = int(s4) * g
    
    t4_prime = sum_s_prime_e_prime + (-term_challenge) + (-term_s4)
    t4_check = (t4 == t4_prime)

    # Verify t_hat chain
    t_hat_valid = True
    for i in range(N):
        if i == 0:
            prev_c = h
        else:
            prev_c = c_hat[i-1]
        
        t_hat_prime = (-(int(challenge) * c_hat[i])) + (int(s_hat[i]) * g) + (int(s_prime[i]) * prev_c)
        
        if t_hat[i] != t_hat_prime:
            t_hat_valid = False
            break
    
    result = (
        t1_check and
        t2_check and
        t3_check and
        t4_check and
        t_hat_valid
    )
    
    print(f"\n[DEBUG] Final result: {result}")
    print(f"[DEBUG] Summary: t1={t1_check}, t2={t2_check}, t3={t3_check}, t4={t4_check}, t_hat={t_hat_valid}")
    
    return result

# testing shuffle flow
def test_basic_shuffle():
    """ """
    print("\n" + "="*60)
    print("Testing Basic Shuffle Proof with Real Keys")
    print("="*60)
    
    pp = gen.pp
    g = pp.P
    N = 5
    
    print(f"\n1. Generating {N} user keys ...")
    users = []
    e = []
    
    for i in range(N):
        user_id = f"User_{i}"
        ((id, (pk, pp_user, proof)), sk) = gen.skey_gen(user_id, pp)
        users.append({
            'id': user_id,
            'pk': pk,
            'sk': sk,
            'proof': proof
        })
        e.append(pk)
        print(f"   {user_id}: pk={str(pk)[:50]}...")
    
    print(f"\n2. Shuffling and anonymizing public keys...")
    e_prime, r_prime, ψ = GenShuffle(e) 
    print(f"   Permutation: {ψ}")
    
    print(f"\n3. Generating shuffle proof (πmix)...")
    proof = GenProof(e, e_prime, r_prime, ψ, g)
    
    print(f"\n4. Verifying shuffle proof...")
    is_valid = verify_shuffle_proof(proof, e, e_prime, g)
    
    print(f"\n{'='*60}")
    print(f"Result: {'✅ PASS' if is_valid else '❌ FAIL'}")
    print(f"{'='*60}\n")
    
    return is_valid

def test_integration_with_aggregator():
    """ """
    print("\n" + "="*60)
    print("Testing Full Integration Flow")
    print("="*60)
    
    pp = gen.pp
    g = pp.P
    N = 5
    
    ID_pk = []
    user_data = {}
    
    for i in range(N):
        user_id = f"A{i}"
        ((id, (pk, pp_user, proof)), sk) = gen.skey_gen(user_id, pp)
        ID_pk.append((user_id, pk))
        user_data[user_id] = {'pk': pk, 'sk': sk}
    
    print(f"\n2. Aggregator mixes public keys...")
    e = [pk for _, pk in ID_pk]
    e_prime, r_prime, ψ = GenShuffle(e)
    πmix = GenProof(e, e_prime, r_prime, ψ, g)
    
    r_map = {}
    for i, (user_id, original_pk) in enumerate(ID_pk):
        shuffled_pos = ψ.index(i)
        r_map[user_id] = r_prime[i]
    
    print(f"\n3. Verifying shuffle proof...")
    is_valid = verify_shuffle_proof(πmix, e, e_prime, g)
    
    print(f"\n4. Users verify they can use anonymized keys...")
    all_verified = True
    for i, (user_id, original_pk) in enumerate(ID_pk):
        r_val = r_map[user_id]
        shuffled_pos = ψ.index(i)
        
        blinding_point = int(r_val) * g
        expected_pk = original_pk + blinding_point
        
        if expected_pk == e_prime[shuffled_pos]:
            print(f"   ✓ {user_id} verified")
        else:
            print(f"   ✗ {user_id} FAILED verification")
            all_verified = False
    
    print(f"\n{'='*60}")
    print(f"Overall: {'✅ PASS' if (is_valid and all_verified) else '❌ FAIL'}")
    print(f"{'='*60}\n")
    
    return is_valid and all_verified

if __name__ == "__main__":
    test_basic_shuffle()
    test_integration_with_aggregator()