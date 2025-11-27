# # Reading material at voting17_HLKD17.pdf

# import hashlib
# import random
# import utils.generators as gen
# from petlib.bn import Bn

# # TODO this is old code, the corrected is outcommented below (havent inserted into rest of the program yet)
# def get_h_generators(N):
#     """ """
#     _, g, order = gen.pp
#     h_generators_local = []
    
#     for i in range(N):
#         # Use random scalar
#         h_scalar = order.random()
#         h_i_point = g.pt_mul(h_scalar)
#         h_generators_local.append(h_i_point)
#     # for i in range(N):
#     #     # Deterministic generation: hash index to get scalar
#     #     h_seed = hashlib.sha256(f"h_generator_{i}".encode()).digest()
#     #     h_scalar = Bn.from_binary(h_seed) % order
#     #     h_i_point = g.pt_mul(h_scalar)
#     #     h_generators_local.append(h_i_point)
    
#     return h_generators_local

# # Generates a random permutation ψ ∈ Ψ_N
# def GenPermutation(N):
#     """ """
#     I = list(range(N))
#     j_i = list(range(N))
#     for i in range(N):
#         k = random.randint(i, N-1)
#         j_i[i] = I[k]
#         I[k] = I[i]
#     return j_i

# # Generates a random permutation ψ ∈ Ψ_N and use it to shuffle a
# # given list e of pk_i into a shuffled list e′.
# # then genshuffle anonymises the list with a random number form the curve 
# def GenShuffle(e):
#     """ """
#     N = len(e)
#     ψ = GenPermutation(N)
#     _, _, order = gen.pp
    
#     r_prime = []
#     e_prime = []

#     for i in range(N):
#         r_i = order.random()
#         r_prime.append(r_i)

#         # anonymised pk with r_i
#         # pk_prime = e[i][1][0].pt_mul(r_i)
#         pk_prime = e[i].pt_mul(r_i)

#         e_prime.append(pk_prime)

#     # shuffle it
#     e_prime_shuffled = [e_prime[ψ[j]] for j in range(N)]
#     return (e_prime_shuffled, r_prime, ψ)

# # GenCommitment() generates a commitment c = Com(ψ, r) to a permutation ψ by
# # committing to the columns of the corresponding permutation matrix.
# # using GenCommitment() is to hide the permutation ψ in the shuffle proof
# def GenCommitment(ψ, h_gens):
#     """ """
#     _, g, order = gen.pp
#     N = len(ψ)
#     c = []
#     r = []

#     for i in range(N):
#         r_j_i = order.random()
#         r.append(r_j_i) # randomness for each commitment

#         j = ψ[i]
        
#         #From g^r * h since we are using ecc and that makes the group additive, 
#         # so ^ becomes *,  * becomes + and mod p is handled by the curve
#         # pedersen commitment               c = g^r_j_i * h_i mod p
#         # pedersen commitment (ecc)         c = r_j_i * g + h_i
#         c_j_i = h_gens[j].pt_add(g.pt_mul(r_j_i)) # commitments 
#         c.append(c_j_i)

#     return (c, r)

# def GenCommitmentChain(c0, u):
#     """ """
#     _, g, order = gen.pp
#     N = len(u)
#     c = []
#     r = []

#     for i in range(N):
#         r_i = order.random()
#         r.append(r_i)
        
#         # start with c0
#         if i == 0:
#             prev_c = c0
#         else:
#             prev_c = c[i - 1]
         
#         # sequential chain where each commitment depends on prev_c, i.e. c0 -> c1 -> ... -> cN
#         # How? by linking the challenges u_i to the commitments
#         # multiplicable version     c_i ← g^{r_i} c_{i-1}^u_i
#         # ecc version               c_i = r_i * g + u_i * c_{i-1}
#         c_i = g.pt_mul(r_i).pt_add(prev_c.pt_mul(u[i]))
#         c.append(c_i)

#         prev_c = c_i
    
#     return (c, r)

# def hash_to_zq(data):
#     """ """
#     hasher = hashlib.sha256()
#     hasher.update(str(data).encode())
#     return Bn.from_binary(hasher.digest())

# # pk for ours is ek
# def GenProof(e, e_prime, r_prime, ψ, pk):
#     """ """
#     _, g, order = gen.pp
#     N = len(e)
#     q = order

#     # get h
#     h_gens = get_h_generators(N)

#     # Step 1: Commit to permutation
#     c, r = GenCommitment(ψ, h_gens)

#     # Step 2-7: Generate challenges
#     u = []
#     for i in range(N):
#         u_i = hash_to_zq((str(e), str(e_prime), str(c), i))
#         # print(f"genproof u is -> " + str(u_i))
#         u.append(u_i)

#     # Step 3: Permute challenges
#     u_prime = [None] * N
#     for i in range(N):
#         u_prime[ψ[i]] = u[i]
        
#     # GenCommitmentChain
#     h = g.pt_mul(order.random()) 
#     c_hat, r_hat = GenCommitmentChain(h, u_prime)

#     # Step 8-14: Compute weighted sums
#     r_bar = sum(r) % q

#     v = [0] * N
#     v[N-1] = 1
#     for i in range(N-2, -1, -1):
#         v[i] = (u_prime[i+1] * v[i+1]) % q
    
#     r_hat_sum = sum((r_hat[i] * v[i]) % q for i in range(N)) % q
#     r_tilde = sum((r[i] * u[i]) % q for i in range(N)) % q
#     r_prime_sum = sum((r_prime[i] * u_prime[i]) % q for i in range(N)) % q

#     # Step 15-25: Generate witnesses
#     w = [order.random() for _ in range(4)]
#     w_hat = [order.random() for _ in range(N)]
#     w_prime = [order.random() for _ in range(N)]

#     # t-values (commitments)
#     t1 = g.pt_mul(w[0])
#     t2 = g.pt_mul(w[1])
#     t3 = g.pt_mul(w[2])
#     for i in range(N):
#         t3 = t3.pt_add(h_gens[i].pt_mul(w_prime[i]))
    
#     ##### TODO review
#     # t4: hyper
#     t_4_1 = e[0].pt_mul(u[0])  # Σ(u_i * e_i)
#     for i in range(1, N):
#         t_4_1 = t_4_1.pt_add(e[i].pt_mul(u[i]))
    
#     t_4_1 = t_4_1.pt_mul(w[3])  # Multiply by witness w[3]
    
#     t_4_2 = e_prime[0].pt_mul(w_prime[0])  # Σ(w'_i * e'_i)
#     for i in range(1, N):
#         t_4_2 = t_4_2.pt_add(e_prime[i].pt_mul(w_prime[i]))
    
#     t4 = t_4_1.pt_add(t_4_2) 

#     t_hat = []
#     for i in range(N):
#         if i == 0:
#             prev_c = h
#         else:
#             prev_c = c_hat[i-1]
        
#         hat_t_i = g.pt_mul(w_hat[i]).pt_add(prev_c.pt_mul(w_prime[i]))
#         t_hat.append(hat_t_i)
    
#     # Step 26-27: Compute challenge
#     y = (str(e), str(e_prime), str(c), str(c_hat), str(pk))
#     t = (str(t1), str(t2), str(t3), str(t4), str(t_hat))
#     challenge = hash_to_zq((y, t))

#     # Step 28-33: Compute responses
#     s1 = (w[0] + challenge * r_bar) % q
#     s2 = (w[1] + challenge * r_hat_sum) % q
#     s3 = (w[2] + challenge * r_tilde) % q
#     s4 = (w[3] + challenge * r_prime_sum) % q

#     s_hat = [(w_hat[i] + challenge * r_hat[i]) % q for i in range(N)]
#     s_prime = [(w_prime[i] + challenge * u_prime[i]) % q for i in range(N)]

#     sum_u_e = e[0].pt_mul(u[0])
#     for i in range(1, N):
#         sum_u_e = sum_u_e.pt_add(e[i].pt_mul(u[i]))
#     # print(f"[GenProof] sum_u_e: {sum_u_e}")

#     sum_sprime_eprime = e_prime[0].pt_mul(s_prime[0])
#     for i in range(1, N):
#         sum_sprime_eprime = sum_sprime_eprime.pt_add(e_prime[i].pt_mul(s_prime[i]))
#     # print(f"[GenProof] sum_sprime_eprime: {sum_sprime_eprime}")

#     proof = {
#         't': (t1, t2, t3, t4, t_hat),
#         's': (s1, s2, s3, s4, s_hat, s_prime),
#         'c': c,
#         'c_hat': c_hat,
#         'h': h,
#         'h_gens': h_gens, # so the h's are deterministic and not re-randomized
#     }

#     return proof

# def verify_shuffle_proof(proof, e, e_prime, pk):
#     """ """
#     _, g, order = gen.pp 
#     N = len(e)
    
#     # Extract proof components
#     t1, t2, t3, t4, t_hat = proof["t"]
#     s1, s2, s3, s4, s_hat, s_prime = proof["s"]
#     c = proof["c"]
#     c_hat = proof["c_hat"]
#     h = proof["h"]
#     h_gens = proof["h_gens"]
    
#     # Recompute challenges u (line 2-3)
#     u = []
#     for i in range(N):
#         u_i = hash_to_zq((str(e), str(e_prime), str(c), i))
#         # print("check u is -> " + str(u_i))
#         u.append(u_i)
    
#     # Line 5: c_bar = Σc_i - Σh_i (point addition in ECC)
#     c_bar = c[0]
#     for i in range(1, N):
#         c_bar = c_bar.pt_add(c[i])
    
#     h_sum = h_gens[0]
#     for i in range(1, N):
#         h_sum = h_sum.pt_add(h_gens[i])
    
#     c_bar = c_bar.pt_add(h_sum.pt_neg())
    
#     # Line 6: u_product = ∏u_i (scalar multiplication)
#     u_product = 1
#     for i in range(N):
#         u_product = (u_product * u[i]) % order
    
#     # Line 7: c_hat_final = c_hat[N-1] - u_product * h
#     c_hat_final = c_hat[N-1].pt_add(h.pt_mul(u_product).pt_neg())
    
#     # Line 8: c_tilde = Σ(u_i * c_i)
#     c_tilde = c[0].pt_mul(u[0])
#     for i in range(1, N):
#         c_tilde = c_tilde.pt_add(c[i].pt_mul(u[i]))
    
#     # Line 10-11: Recompute challenge
#     y = (str(e), str(e_prime), str(c), str(c_hat), str(pk))
#     t = (str(t1), str(t2), str(t3), str(t4), str(t_hat))
#     challenge = hash_to_zq((y, t))
    
#     # Line 12: Verify t1 = -challenge*c_bar + s1*g
#     t1_prime = c_bar.pt_mul(challenge).pt_neg().pt_add(g.pt_mul(s1))
#     t1_check = (t1 == t1_prime)
    
#     # Line 13: Verify t2 = -challenge*c_hat_final + s2*g
#     t2_prime = c_hat_final.pt_mul(challenge).pt_neg().pt_add(g.pt_mul(s2))
#     t2_check = (t2 == t2_prime)
    
#     # Line 14: Verify t3 = -challenge*c_tilde + s3*g + Σ(s'_i*h_i)
#     t3_prime_1 = c_tilde.pt_mul(challenge).pt_neg()
#     t3_prime_2 = g.pt_mul(s3)
#     t3_prime_prod = h_gens[0].pt_mul(s_prime[0])
    
#     for i in range(1, N):
#         t3_prime_prod = t3_prime_prod.pt_add(h_gens[i].pt_mul(s_prime[i]))
    
#     t3_prime = t3_prime_1.pt_add(t3_prime_2).pt_add(t3_prime_prod)
    
#     t3_check = (t3 == t3_prime)

#     # Verify t4
#     # print(f"[DEBUG] check what e[0]:" + str(e[0])[:60] + "...")
#     # sum_u_e = e[0].pt_mul(u[0])
#     # for i in range(1, N):
#     #     sum_u_e = sum_u_e.pt_add(e[i].pt_mul(u[i]))

#     # # Compute Σ(s'_i * e'_i)
#     # sum_sprime_eprime = e_prime[0].pt_mul(s_prime[0])
#     # for i in range(1, N):
#     #     sum_sprime_eprime = sum_sprime_eprime.pt_add(e_prime[i].pt_mul(s_prime[i]))
    
#     # # Compute Σ(e'_i)
#     # sum_e_prime = e_prime[0]
#     # for i in range(1, N):
#     #     sum_e_prime = sum_e_prime.pt_add(e_prime[i])

#     # # t4' = s4 * Σ(u_i * e_i) + Σ(s'_i * e'_i) - challenge * Σ(u_i * e_i) - challenge * Σ(e'_i)
#     # t4_prime = sum_u_e.pt_mul(s4)
#     # t4_prime = t4_prime.pt_add(sum_sprime_eprime)
#     # t4_prime = t4_prime.pt_add(sum_u_e.pt_mul(challenge).pt_neg())
#     # t4_prime = t4_prime.pt_add(sum_e_prime.pt_mul(challenge).pt_neg())

#     # print(f"[DEBUG CheckProof] t4_prime: {t4_prime}")
#     # print(f"[DEBUG CheckProof] t4: {t4}")

#     # t4_check = (t4 == t4_prime)

#     # print(f"[DEBUG] t4 check: {t4_check}")

#     # Line 16-17: Verify t_hat chain
#     t_hat_valid = True
#     for i in range(N):
#         if i == 0:
#             prev_c = h
#         else:
#             prev_c = c_hat[i-1]
        
#         # t_hat'_i = -challenge*c_hat[i] + s_hat[i]*g + s'_i*prev_c
#         t_hat_prime = c_hat[i].pt_mul(challenge).pt_neg()
#         t_hat_prime = t_hat_prime.pt_add(g.pt_mul(s_hat[i]))
#         t_hat_prime = t_hat_prime.pt_add(prev_c.pt_mul(s_prime[i]))
        
#         if t_hat[i] != t_hat_prime:
#             t_hat_valid = False
#             print(f"[DEBUG] t_hat[{i}] check: FAIL")
#             break
#         else:
#             print(f"[DEBUG] t_hat[{i}] check: PASS")
    
#     result = (
#         t1_check and
#         t2_check and
#         t3_check and
#         # t4_check and
#         t_hat_valid
#     )
    
#     print(f"\n[DEBUG] Final result: {result}")
#     print(f"[DEBUG] Summary: t1={t1_check}, t2={t2_check}, t3={t3_check}, t_hat={t_hat_valid}")
    
#     return result

# # testing shuffle flow
# def test_basic_shuffle():
#     """ """
#     print("\n" + "="*60)
#     print("Testing Basic Shuffle Proof with Real Keys")
#     print("="*60)
    
#     pp = gen.pp
#     _, g, order = pp
#     N = 5
    
#     print(f"\n1. Generating {N} user keys ...")
#     users = []
#     e = []  # List of public keys to shuffle
    
#     for i in range(N):
#         # Generate keys for users
#         user_id = f"User_{i}"
#         ((id, (pk, pp_user, proof)), sk) = gen.skey_gen(user_id, pp)
#         users.append({
#             'id': user_id,
#             'pk': pk,
#             'sk': sk,
#             'proof': proof
#         })
#         e.append(pk)  # Add public key to list
#         print(f"   {user_id}: pk={str(pk)[:50]}...")
    
#     print(f"\n2. Shuffling and anonymizing public keys...")
#     e_prime, r_prime, ψ = GenShuffle(e) 
#     print(f"   Permutation: {ψ}")
#     print(f"   Original order: User_0, User_1, User_2, User_3, User_4")
#     shuffled_order = [f"User_{ψ.index(i)}" for i in range(N)]
#     print(f"   Shuffled order: {', '.join(shuffled_order)}")
    
#     print(f"\n3. Generating shuffle proof (πmix)...")

#     pk_for_proof = g 
#     proof = GenProof(e, e_prime, r_prime, ψ, pk_for_proof)
#     print(f"   Proof generated with:")
#     print(f"   - Commitments (c): {len(proof['c'])} elements")
#     print(f"   - Commitment chain (c_hat): {len(proof['c_hat'])} elements")
#     print(f"   - Responses (s): 6 values")
    
#     print(f"\n4. Verifying shuffle proof...")
#     is_valid = verify_shuffle_proof(proof, e, e_prime, pk_for_proof)
    
#     print(f"\n{'='*60}")
#     print(f"Result: {'✅ PASS' if is_valid else '❌ FAIL'}")
#     print(f"{'='*60}")
    
#     if is_valid:
#         print("\n Anonymization Summary:")
#         print("   ✓ Public keys successfully shuffled and re-randomized")
#         print("   ✓ Zero-knowledge proof verified")
#         print("   ✓ Original identities hidden (permutation secret)")
#         print("   ✓ Users can still use their keys with r' for operations")
    
#     print()
#     return is_valid

# def test_integration_with_aggregator():
#     """ """
#     print("\n" + "="*60)
#     print("Testing Full Integration Flow")
#     print("="*60)
    
#     pp = gen.pp
#     _, g, _ = pp
#     N = 5
    
#     # print(f"\n1. Users register with aggregator...")
#     ID_pk = []
#     user_data = {}
    
#     for i in range(N):
#         user_id = f"A{i}"
#         ((id, (pk, pp_user, proof)), sk) = gen.skey_gen(user_id, pp)
#         ID_pk.append((user_id, pk))
#         user_data[user_id] = {'pk': pk, 'sk': sk}
#         # print(f"   {user_id} registered: pk={str(pk)[:40]}...")
    
#     print(f"\n2. Aggregator mixes public keys...")
#     # Extract just the public keys
#     e = [pk for _, pk in ID_pk]
    
#     # Perform shuffle
#     e_prime, r_prime, ψ = GenShuffle(e)
    
#     # Generate proof
#     πmix = GenProof(e, e_prime, r_prime, ψ, g)
    
#     # print(f"   Shuffle complete with permutation: {ψ}")
#     # print(f"   Permutation meaning: position j gets element from position ψ[j]")
    
#     r_map = {}
#     for i, (user_id, original_pk) in enumerate(ID_pk):
#         # User i's key was re-randomized with r_prime[i]
#         # Then placed at position j where ψ[j] = i
#         # Find that position j
#         shuffled_pos = ψ.index(i)  # Find j where ψ[j] = i
        
#         r_map[user_id] = r_prime[i]  # User gets their own r_prime[i]
#         # print(f"   {user_id} (original pos {i}) → shuffled pos {shuffled_pos}, r'={str(r_prime[i])[:40]}...")
    
#     print(f"\n3. Verifying shuffle proof...")
#     is_valid = verify_shuffle_proof(πmix, e, e_prime, g)
    
#     print(f"\n4. Users verify they can use anonymized keys...")
#     all_verified = True
#     for i, (user_id, original_pk) in enumerate(ID_pk):
#         r_val = r_map[user_id]
        
#         # Find where this user's key ended up
#         shuffled_pos = ψ.index(i)
        
#         # Compute expected: pk' = pk * r'
#         expected_pk = original_pk.pt_mul(r_val)
        
#         # Check if it matches the shuffled position
#         if expected_pk == e_prime[shuffled_pos]:
#             print(f"   ✓ {user_id} verified: e_prime[{shuffled_pos}] = e[{i}] * r'[{i}]")
#         else:
#             print(f"   ✗ {user_id} FAILED verification")
#             print(f"      Expected at pos {shuffled_pos}: {str(expected_pk)[:50]}")
#             print(f"      Got: {str(e_prime[shuffled_pos])[:50]}")
#             all_verified = False
    
#     print(f"\n{'='*60}")
#     print(f"Shuffle Proof: {'✅ PASS' if is_valid else '❌ FAIL'}")
#     print(f"User Verification: {'✅ PASS' if all_verified else '❌ FAIL'}")
#     print(f"Overall: {'✅ PASS' if (is_valid and all_verified) else '❌ FAIL'}")
#     print(f"{'='*60}\n")
    
#     return is_valid and all_verified

# if __name__ == "__main__":
#     # Test 1: Basic shuffle with generated keys
#     test_basic_shuffle()
    
#     # Test 2: Full integration flow
#     print("\n\n")
#     test_integration_with_aggregator()


# corrected code
# TODO integrate with rest of the program now that it changed
import hashlib
import random
import utils.generators as gen
from petlib.bn import Bn

# main
def get_h_generators(N):
    """ """
    _, g, order = gen.pp
    h_generators_local = []
    
    for i in range(N):
        # Use random scalar
        h_scalar = order.random()
        h_i_point = g.pt_mul(h_scalar)
        h_generators_local.append(h_i_point)
    # for i in range(N):
    #     # Deterministic generation: hash index to get scalar
    #     h_seed = hashlib.sha256(f"h_generator_{i}".encode()).digest()
    #     h_scalar = Bn.from_binary(h_seed) % order
    #     h_i_point = g.pt_mul(h_scalar)
    #     h_generators_local.append(h_i_point)
    
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

# Generates a random permutation ψ ∈ Ψ_N and use it to shuffle a
# given list e of pk_i into a shuffled list e′.
# then genshuffle anonymises the list with a random number form the curve 
# def GenShuffle(e):
#     """ """
#     N = len(e)
#     ψ = GenPermutation(N)
#     _, _, order = gen.pp
    
#     r_prime = []
#     e_prime = []

#     for i in range(N):
#         r_i = order.random()
#         r_prime.append(r_i)

#         # anonymised pk with r_i
#         # pk_prime = e[i][1][0].pt_mul(r_i)
#         pk_prime = e[i].pt_mul(r_i)

#         e_prime.append(pk_prime)

#     # shuffle it
#     e_prime_shuffled = [e_prime[ψ[j]] for j in range(N)]
#     return (e_prime_shuffled, r_prime, ψ)
def GenShuffle(e):
    """ """
    N = len(e)
    ψ = GenPermutation(N)
    _, g, order = gen.pp
    
    r_prime = []
    e_prime = []

    for i in range(N):
        r_i = order.random()
        r_prime.append(r_i)

        # Trying additive blinding e[i] + r_i * G
        # This shifts the point rather than scaling it
        blinding_factor = g.pt_mul(r_i)
        pk_prime = e[i].pt_add(blinding_factor)

        e_prime.append(pk_prime)

    # shuffle it
    e_prime_shuffled = [e_prime[ψ[j]] for j in range(N)]
    return (e_prime_shuffled, r_prime, ψ)

# GenCommitment() generates a commitment c = Com(ψ, r) to a permutation ψ by
# committing to the columns of the corresponding permutation matrix.
# using GenCommitment() is to hide the permutation ψ in the shuffle proof
def GenCommitment(ψ, h_gens):
    """ 
    Commits to the permutation matrix.
    To match the shuffle logic (e'[j] = e[ψ[j]]) and challenge logic (u'[j] = u[ψ[j]]),
    we must structure the commitment such that c[ψ[i]] commits to h[i].
    """
    _, g, order = gen.pp
    N = len(ψ)
    
    # Pre-allocate list because we will fill it out of order
    c = [None] * N 
    r = []

    # Generate randomness for all N commitments
    for _ in range(N):
        r.append(order.random())

    for i in range(N):
        # i is the original index.
        # j is the target index where i moves to.
        j = ψ[i]
        
        # The commitment at the target position (j) must contain the generator 
        # corresponding to the original position (i).
        # Formula: c[j] = r[j] * G + h_gens[i]
        
        # 1. Calculate term: h_gens[i]
        h_term = h_gens[i]
        
        # 2. Calculate term: r[j] * G
        g_term = g.pt_mul(r[j])
        
        # 3. Combine
        c[j] = h_term.pt_add(g_term)

    return (c, r)

def GenCommitmentChain(c0, u):
    """ """
    _, g, order = gen.pp
    N = len(u)
    c = []
    r = []

    for i in range(N):
        r_i = order.random()
        r.append(r_i)
        
        # start with c0
        if i == 0:
            prev_c = c0
        else:
            prev_c = c[i - 1]
         
        # sequential chain where each commitment depends on prev_c, i.e. c0 -> c1 -> ... -> cN
        # How? by linking the challenges u_i to the commitments
        # multiplicable version     c_i ← g^{r_i} c_{i-1}^u_i
        # ecc version               c_i = r_i * g + u_i * c_{i-1}
        c_i = g.pt_mul(r_i).pt_add(prev_c.pt_mul(u[i]))
        c.append(c_i)

        prev_c = c_i
    
    return (c, r)

def hash_to_zq(data):
    """ """
    hasher = hashlib.sha256()
    hasher.update(str(data).encode())
    return Bn.from_binary(hasher.digest())

# pk for ours is ek
def GenProof(e, e_prime, r_prime, ψ, pk):
    """ """
    _, g, order = gen.pp
    N = len(e)
    q = order

    # get h
    h_gens = get_h_generators(N)

    # Step 1: Commit to permutation
    c, r = GenCommitment(ψ, h_gens)

    # Step 2-7: Generate challenges
    u = []
    for i in range(N):
        u_i = hash_to_zq((str(e), str(e_prime), str(c), i))
        u.append(u_i)

    # ψ maps New_Index -> Old_Index. 
    # So u_prime[j] (new) must equal u[ψ[j]] (old).
    u_prime = [u[ψ[j]] for j in range(N)]
        
    # GenCommitmentChain
    h = g.pt_mul(order.random()) 
    c_hat, r_hat = GenCommitmentChain(h, u_prime)

    # Step 8-14: Compute weighted sums
    r_bar = sum(r) % q

    v = [0] * N
    v[N-1] = 1
    for i in range(N-2, -1, -1):
        v[i] = (u_prime[i+1] * v[i+1]) % q
    
    r_hat_sum = sum((r_hat[i] * v[i]) % q for i in range(N)) % q
    r_tilde = sum((r[i] * u[i]) % q for i in range(N)) % q

    # We need Σ(u'_i * r'_shuffled_i). 
    # Since u' and r' are both permuted by ψ, this equals Σ(u_original * r_original).
    # Your r_prime input is in original order. Your u is in original order.
    r_prime_sum = sum((r_prime[i] * u[i]) % q for i in range(N)) % q

    # Step 15-25: Generate witnesses
    w = [order.random() for _ in range(4)]
    w_hat = [order.random() for _ in range(N)]
    w_prime = [order.random() for _ in range(N)]

    # t-values (commitments)
    t1 = g.pt_mul(w[0])
    t2 = g.pt_mul(w[1])
    t3 = g.pt_mul(w[2])
    for i in range(N):
        t3 = t3.pt_add(h_gens[i].pt_mul(w_prime[i]))
    
    # t4 = Σ(w'_i * e'_i) - w[3] * G
    
    # Part A: Σ(w'_i * e'_i)
    sum_w_prime_e_prime = e_prime[0].pt_mul(w_prime[0])
    for i in range(1, N):
        sum_w_prime_e_prime = sum_w_prime_e_prime.pt_add(e_prime[i].pt_mul(w_prime[i]))
    
    # Part B: w[3] * G
    w3_g = g.pt_mul(w[3])
    
    # t4 calculation
    t4 = sum_w_prime_e_prime.pt_add(w3_g.pt_neg()) 

    t_hat = []
    for i in range(N):
        if i == 0:
            prev_c = h
        else:
            prev_c = c_hat[i-1]
        
        hat_t_i = g.pt_mul(w_hat[i]).pt_add(prev_c.pt_mul(w_prime[i]))
        t_hat.append(hat_t_i)
    
    # Step 26-27: Compute challenge
    y = (str(e), str(e_prime), str(c), str(c_hat), str(pk))
    t = (str(t1), str(t2), str(t3), str(t4), str(t_hat))
    challenge = hash_to_zq((y, t))

    # Step 28-33: Compute responses
    s1 = (w[0] + challenge * r_bar) % q
    s2 = (w[1] + challenge * r_hat_sum) % q
    s3 = (w[2] + challenge * r_tilde) % q
    s4 = (w[3] + challenge * r_prime_sum) % q

    s_hat = [(w_hat[i] + challenge * r_hat[i]) % q for i in range(N)]
    s_prime = [(w_prime[i] + challenge * u_prime[i]) % q for i in range(N)]

    proof = {
        't': (t1, t2, t3, t4, t_hat),
        's': (s1, s2, s3, s4, s_hat, s_prime),
        'c': c,
        'c_hat': c_hat,
        'h': h,
        'h_gens': h_gens,
    } 
    """ 
    tuple[tuple[EcPt, EcPt, EcPt, EcPt, list[EcPt]], 
        tuple[Bn, Bn, Bn, Bn, list[Bn], list[Bn]], 
        list[EcPt],
        list[EcPt],
        EcPt,
        list[EcPt]]
    """

    return proof

def verify_shuffle_proof(proof, e, e_prime, pk):
    """ """
    _, g, order = gen.pp 
    N = len(e)
    
    # Extract proof components
    t1, t2, t3, t4, t_hat = proof["t"]
    s1, s2, s3, s4, s_hat, s_prime = proof["s"]
    c = proof["c"]
    c_hat = proof["c_hat"]
    h = proof["h"]
    h_gens = proof["h_gens"]
    
    # Recompute challenges u (line 2-3)
    u = []
    for i in range(N):
        u_i = hash_to_zq((str(e), str(e_prime), str(c), i))
        # print("check u is -> " + str(u_i))
        u.append(u_i)
    
    # Line 5: c_bar = Σc_i - Σh_i (point addition in ECC)
    c_bar = c[0]
    for i in range(1, N):
        c_bar = c_bar.pt_add(c[i])
    
    h_sum = h_gens[0]
    for i in range(1, N):
        h_sum = h_sum.pt_add(h_gens[i])
    
    c_bar = c_bar.pt_add(h_sum.pt_neg())
    
    # Line 6: u_product = ∏u_i (scalar multiplication)
    u_product = 1
    for i in range(N):
        u_product = (u_product * u[i]) % order
    
    # Line 7: c_hat_final = c_hat[N-1] - u_product * h
    c_hat_final = c_hat[N-1].pt_add(h.pt_mul(u_product).pt_neg())
    
    # Line 8: c_tilde = Σ(u_i * c_i)
    c_tilde = c[0].pt_mul(u[0])
    for i in range(1, N):
        c_tilde = c_tilde.pt_add(c[i].pt_mul(u[i]))
    
    # Line 10-11: Recompute challenge
    y = (str(e), str(e_prime), str(c), str(c_hat), str(pk))
    t = (str(t1), str(t2), str(t3), str(t4), str(t_hat))
    challenge = hash_to_zq((y, t))
    
    # Line 12: Verify t1 = -challenge*c_bar + s1*g
    t1_prime = c_bar.pt_mul(challenge).pt_neg().pt_add(g.pt_mul(s1))
    t1_check = (t1 == t1_prime)
    
    # Line 13: Verify t2 = -challenge*c_hat_final + s2*g
    t2_prime = c_hat_final.pt_mul(challenge).pt_neg().pt_add(g.pt_mul(s2))
    t2_check = (t2 == t2_prime)
    
    # Line 14: Verify t3 = -challenge*c_tilde + s3*g + Σ(s'_i*h_i)
    t3_prime_1 = c_tilde.pt_mul(challenge).pt_neg()
    t3_prime_2 = g.pt_mul(s3)
    t3_prime_prod = h_gens[0].pt_mul(s_prime[0])
    
    for i in range(1, N):
        t3_prime_prod = t3_prime_prod.pt_add(h_gens[i].pt_mul(s_prime[i]))
    
    t3_prime = t3_prime_1.pt_add(t3_prime_2).pt_add(t3_prime_prod)
    
    t3_check = (t3 == t3_prime)

    # t4_prime = Σ(s'_i * e'_i) - c * Σ(u_i * e_i) - s4 * G

    # Compute Σ(s'_i * e'_i)
    sum_s_prime_e_prime = e_prime[0].pt_mul(s_prime[0])
    for i in range(1, N):
        sum_s_prime_e_prime = sum_s_prime_e_prime.pt_add(e_prime[i].pt_mul(s_prime[i]))
    
    # Compute Σ(u_i * e_i)
    sum_u_e = e[0].pt_mul(u[0])
    for i in range(1, N):
        sum_u_e = sum_u_e.pt_add(e[i].pt_mul(u[i]))

    # Assemble
    term_challenge = sum_u_e.pt_mul(challenge)
    term_s4 = g.pt_mul(s4)
    
    t4_prime = sum_s_prime_e_prime.pt_add(term_challenge.pt_neg()).pt_add(term_s4.pt_neg())
    
    t4_check = (t4 == t4_prime)
    print(f"[DEBUG] t4 check: {t4_check}")

    # Line 16-17: Verify t_hat chain
    t_hat_valid = True
    for i in range(N):
        if i == 0:
            prev_c = h
        else:
            prev_c = c_hat[i-1]
        
        # t_hat'_i = -challenge*c_hat[i] + s_hat[i]*g + s'_i*prev_c
        t_hat_prime = c_hat[i].pt_mul(challenge).pt_neg()
        t_hat_prime = t_hat_prime.pt_add(g.pt_mul(s_hat[i]))
        t_hat_prime = t_hat_prime.pt_add(prev_c.pt_mul(s_prime[i]))
        
        if t_hat[i] != t_hat_prime:
            t_hat_valid = False
            print(f"[DEBUG] t_hat[{i}] check: FAIL")
            break
        else:
            print(f"[DEBUG] t_hat[{i}] check: PASS")
    
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
    _, g, order = pp
    N = 5
    
    print(f"\n1. Generating {N} user keys ...")
    users = []
    e = []  # List of public keys to shuffle
    
    for i in range(N):
        # Generate keys for users
        user_id = f"User_{i}"
        ((id, (pk, pp_user, proof)), sk) = gen.skey_gen(user_id, pp)
        users.append({
            'id': user_id,
            'pk': pk,
            'sk': sk,
            'proof': proof
        })
        e.append(pk)  # Add public key to list
        print(f"   {user_id}: pk={str(pk)[:50]}...")
    
    print(f"\n2. Shuffling and anonymizing public keys...")
    e_prime, r_prime, ψ = GenShuffle(e) 
    print(f"   Permutation: {ψ}")
    print(f"   Original order: User_0, User_1, User_2, User_3, User_4")
    shuffled_order = [f"User_{ψ.index(i)}" for i in range(N)]
    print(f"   Shuffled order: {', '.join(shuffled_order)}")
    
    print(f"\n3. Generating shuffle proof (πmix)...")

    pk_for_proof = g 
    proof = GenProof(e, e_prime, r_prime, ψ, pk_for_proof)
    print(f"   Proof generated with:")
    print(f"   - Commitments (c): {len(proof['c'])} elements")
    print(f"   - Commitment chain (c_hat): {len(proof['c_hat'])} elements")
    print(f"   - Responses (s): 6 values")
    
    print(f"\n4. Verifying shuffle proof...")
    is_valid = verify_shuffle_proof(proof, e, e_prime, pk_for_proof)
    
    print(f"\n{'='*60}")
    print(f"Result: {'✅ PASS' if is_valid else '❌ FAIL'}")
    print(f"{'='*60}")
    
    if is_valid:
        print("\n Anonymization Summary:")
        print("   ✓ Public keys successfully shuffled and re-randomized")
        print("   ✓ Zero-knowledge proof verified")
        print("   ✓ Original identities hidden (permutation secret)")
        print("   ✓ Users can still use their keys with r' for operations")
    
    print()
    return is_valid

def test_integration_with_aggregator():
    """ """
    print("\n" + "="*60)
    print("Testing Full Integration Flow")
    print("="*60)
    
    pp = gen.pp
    _, g, _ = pp
    N = 5
    
    # print(f"\n1. Users register with aggregator...")
    ID_pk = []
    user_data = {}
    
    for i in range(N):
        user_id = f"A{i}"
        ((id, (pk, pp_user, proof)), sk) = gen.skey_gen(user_id, pp)
        ID_pk.append((user_id, pk))
        user_data[user_id] = {'pk': pk, 'sk': sk}
        # print(f"   {user_id} registered: pk={str(pk)[:40]}...")
    
    print(f"\n2. Aggregator mixes public keys...")
    # Extract just the public keys
    e = [pk for _, pk in ID_pk]
    
    # Perform shuffle
    e_prime, r_prime, ψ = GenShuffle(e)
    
    # Generate proof
    πmix = GenProof(e, e_prime, r_prime, ψ, g)
    
    # print(f"   Shuffle complete with permutation: {ψ}")
    # print(f"   Permutation meaning: position j gets element from position ψ[j]")
    
    r_map = {}
    for i, (user_id, original_pk) in enumerate(ID_pk):
        # User i's key was re-randomized with r_prime[i]
        # Then placed at position j where ψ[j] = i
        # Find that position j
        shuffled_pos = ψ.index(i)  # Find j where ψ[j] = i
        
        r_map[user_id] = r_prime[i]  # User gets their own r_prime[i]
        # print(f"   {user_id} (original pos {i}) → shuffled pos {shuffled_pos}, r'={str(r_prime[i])[:40]}...")
    
    print(f"\n3. Verifying shuffle proof...")
    is_valid = verify_shuffle_proof(πmix, e, e_prime, g)
    
    print(f"\n4. Users verify they can use anonymized keys...")
    all_verified = True
    for i, (user_id, original_pk) in enumerate(ID_pk):
        r_val = r_map[user_id]
        
        # Find where this user's key ended up
        shuffled_pos = ψ.index(i)
        
        # Compute expected: pk' = pk * r'
        # Multiplicative: expected_pk = original_pk.pt_mul(r_val)
        # Additive:       expected_pk = original_pk + (r_val * G)
        
        blinding_point = g.pt_mul(r_val)
        expected_pk = original_pk.pt_add(blinding_point)
        
        # Check if it matches the shuffled position
        if expected_pk == e_prime[shuffled_pos]:
            print(f"   ✓ {user_id} verified: e_prime[{shuffled_pos}] = e[{i}] * r'[{i}]")
        else:
            print(f"   ✗ {user_id} FAILED verification")
            print(f"      Expected at pos {shuffled_pos}: {str(expected_pk)[:50]}")
            print(f"      Got: {str(e_prime[shuffled_pos])[:50]}")
            all_verified = False
    
    print(f"\n{'='*60}")
    print(f"Shuffle Proof: {'✅ PASS' if is_valid else '❌ FAIL'}")
    print(f"User Verification: {'✅ PASS' if all_verified else '❌ FAIL'}")
    print(f"Overall: {'✅ PASS' if (is_valid and all_verified) else '❌ FAIL'}")
    print(f"{'='*60}\n")
    
    return is_valid and all_verified

if __name__ == "__main__":
    # Test 1: Basic shuffle with generated keys
    test_basic_shuffle()
    
    # Test 2: Full integration flow
    print("\n\n")
    test_integration_with_aggregator()