# Reading material at voting17_HLKD17.pdf

# libraries:
# Verificatum Mix-Net
# UniCrypt library
import random
import utils.generators as gen
from petlib.bn import Bn

h_generators = []

# Generates a random permutation ψ ∈ Ψ_N
def GenPermutation(N):
    I = list(range(N))
    j_i = list(range(N))
    for i in range(N):
        k = random.randint(i, N-1)
        j_i[i] = I[k]
        I[k] = I[i]
    return j_i

# Generates a random permutation ψ ∈ Ψ_N and use it to shuffle a
# given list e of pk_i into a shuffled list e′.
def GenShuffle(e, pk):
    N = len(e)
    ψ = GenPermutation(N)
    _, _, order = gen.pp
    
    r_prime = []
    e_prime = []

    for i in range(N):
        r_i = order.random()
        r_prime.append(r_i)
        
        pk = e[i]
        # pk_prime = pk * pow(g, r_i)
        pk_prime = pk * r_i # make sure the elliptic curve calculation conversion is correct
        
        e_prime.append(pk_prime)

    # shuffle it
    e_prime_shuffled = [e_prime[ψ[j]] for j in range(N)]
    return (e_prime_shuffled, r_prime, ψ)

# GenCommitment() generates a commitment c = Com(ψ, r) to a permutation ψ by
# committing to the columns of the corresponding permutation matrix.
# using GenCommitment() is to hide the permutation ψ in the shuffle proof
def GenCommitment(ψ):
    _, g, order = gen.pp
    N = len(ψ)
    c = []
    r = []

    group = gen.pp[0] # gets the group for h

    for i in range(N):
        # Check if translating a label to a point is more safe then just getting a point on the elliptic curve 
        h_i = group.hash_to_point(f"h_generator_label_{i}".encode()) # creates h, which is a fixed label. (uses petlib's hash_to_point)
        h_generators.append(h_i)

    for i in range(N):
        r_j_i = order.random()
        r.append(r_j_i) # randomness for each commitment

        j = ψ[i]
        
        #From g^r * h since we are using ecc and that makes the group additive, 
        # so ^ becomes *,  * becomes + and mod p is handled by the curve
        # pedersen commitment               c = g^r_j_i * h_i mod p
        # pedersen commitment (ecc)         c = r_j_i * g + h_i
        c_j_i = h_generators[j].pt_add(g.pt_mul(r_j_i)) # commitments 
        c.append(c_j_i)

    return (c, r)

# Test gencommitment
# def testCommitment():
#     N = 4
#     ψ = GenPermutation(N)
#     print("permutations ", ψ)
#     c, r = GenCommitment(ψ)
#     print("the commits ", c)
#     for index, c in enumerate(c):
#         print(f"c[{index}] = {c}")
#     print("the randomness ", r)

# testCommitment()

# GenCommitmentChain() generates a commitment chain c0 → c1 → ... → cN relative to a
# list of public challenges u and starting with a given commitment c0
# using GenCommitmentChain() is to prove consistency in the shuffle proof
def GenCommitmentChain(c0, u):
    _, g, order = gen.pp
    N = len(u)
    c = []
    r = []

    # start with c0
    prev_c = c0

    for i in range(N):
        r_i = order.random()
        r.append(r_i)

        # sequential chain where each commitment depends on prev_c, i.e. c0 -> c1 -> ... -> cN
        # How? by linking the challenges u_i to the commitments
        # multiplicable version     c_i ← g^{r_i} c_{i-1}^u_i
        # ecc version               c_i = r_i * g + u_i * c_{i-1}
        c_i = g.pt_mul(r_i).pt_add(prev_c.pt_mul(u[i]))
        c.append(c_i)

        prev_c = c_i
    
    return (c, r)


# Algorithm 4.3: Generates a proof of shuffle for given ElGamal encryptions e and
# e′ according to Wikström’s method
# GenProof(e, e′, r′, ψ, pk
# Input:
# ElGamal encryptions e = (e1, ... , eN ), e_i = (ai, bi) ∈ G^2_q
# Shuffled ElGamal encryptions e′ = (e′ 1, ... , e′ N ), e′ i = (a′ i, b′ i) ∈ ^2_q
# Re-encryption randomizations r′ = (r′ 1, ... , r′ N ), r′ i ∈ _q
# Permutation ψ = (j1, ... , jN ) ∈ Ψ_N
# Encryption key pk ∈ G
# Wikström's shuffle proof protocol. The proof needs to demonstrate 4 different relations:

# t1: Proves knowledge of r̄ (sum of permutation randomness)
# t2: Proves knowledge of r̂ (weighted sum of chain randomness)
# t3: Proves knowledge of r̃ (weighted permutation randomness)
# t4: Proves knowledge of r'(re-encryption randomness) - this is a pair for ElGamal
import hashlib

def hash_to_zq(data, modulus):
    """Cryptographically secure hash to Zq"""
    hasher = hashlib.sha256()
    hasher.update(str(data).encode())
    return Bn.from_binary(hasher.digest()) % modulus

# TODO review
def GenProof(e, e_prime, r_prime, ψ, pk):
    group, g, order = gen.pp
    N = len(e)
    q = order

    c, r = GenCommitment(ψ)

    u = []
    u_prime = []

    for i in range(N):
        u_i = hash_to_zq((str(e), str(e_prime), str(c), i), q)
        u.append(u_i)
        u_prime.append(u[ψ[i]])

    h = group.hash_to_point(b"label")
    hat_c, hat_r = GenCommitmentChain(h, u_prime)

    # line 8
    r_bar = sum(r) % q

    # lines 9-11
    v = [0] * N
    v[N-1] = 1
    for i in range(N-2,-1,-1):
        v[i] = (u_prime[i+1] * v[i+1]) % q
    
    # line 12-14
    hat_r_sum = sum(hat_r[i] * v[i] for i in range(N)) % q
    r_tilde = sum(r[i] * u[i] for i in range(N)) % q
    r_prime_sum = sum(r_prime[i] * u[i] for i in range(N)) % q

    # line 15-18
    omega = [order.random() for _ in range(4)]
    hat_omega =  [order.random() for _ in range(N)]   # ω2
    omega_prime =  [order.random() for _ in range(N)] # ω3

    # line 19-22
    t1 = g.pt_mul(omega[0])  # g^ω1 mod p → ω1 * g
    t2 = g.pt_mul(omega[1])  # g^ω2 mod p → ω2 * g

    # t3 = g^ω3 * ∏h_i^ω'_i → ω3 * g + Σ(ω'_i * h_i)
    t3 = g.pt_mul(omega[2])
    for i in range(N):
        t3 = t3.pt_add(h_generators[i].pt_mul(omega_prime[i]))
    
    # TODO review
    # ElGamal pairs (AI GENERATED)
    t4_1 = pk.pt_mul(-omega[3])
    t4_2 = g.pt_mul(-omega[3])
    
    for i in range(N):
        a_prime_i, b_prime_i = e_prime[i]
        t4_1 = t4_1.pt_add(a_prime_i.pt_mul(omega_prime[i]))
        t4_2 = t4_2.pt_add(b_prime_i.pt_mul(omega_prime[i]))

    # line 23-25
    hat_c0 = h
    hat_t = []
    for i in range(N):
        prev_c = hat_c0 if i == 0 else hat_c[i-1]
        hat_t_i = g.pt_mul(hat_omega[i]).pt_add(prev_c.pt_mul(omega_prime[i]))
        hat_t.append(hat_t_i)

    # line 26-27
    y = (str(e), str(e_prime), str(c), str(hat_c), str(pk))
    t = (str(t1), str(t2), str(t3), str((t4_1, t4_2)), str(hat_t))
    challenge = hash_to_zq((y, t), q)

    # line 28-33
    s1 = (omega[0] + challenge * r_bar) % q
    s2 = (omega[1] + challenge * hat_r_sum) % q
    s3 = (omega[2] + challenge * r_tilde) % q
    s4 = (omega[3] + challenge * r_prime_sum) % q

    hat_s = [(hat_omega[i] + challenge * hat_r[i]) % q for i in range(N)]
    s_prime = [(omega_prime[i] + challenge * u_prime[i]) % q for i in range(N)]

    # line 34-36
    s = (s1, s2, s3, s4, hat_s, s_prime)
    proof = (t, s, challenge, hat_c)

    return proof

# Algorithm 4.6: Checks the correctness of a shuffle proof π generated by Algo-
# rithm 4.3. The public values are the ElGamal encryptions e and e′ and the public
# encryption key pk.
def CheckProof():
    return ""
