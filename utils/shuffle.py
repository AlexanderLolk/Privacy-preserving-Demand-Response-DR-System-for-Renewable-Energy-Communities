# Reading material at voting17_HLKD17.pdf

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
# keep in mind, this reencrypts the list and then shuffles it
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
        # pk_prime = pk * r_i # make sure the elliptic curve calculation conversion is correct
        pk_prime = pk.pt_mul(r_i)

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

    global h_generators
    h_generators = []

    # TODO make sure we can actually use a correct h
    for i in range(N):
        # Check if translating a label to a point is more safe then just getting a point on the elliptic curve 
        h_i = group.hash_to_point(f"h_generator_label_{i}".encode()) # creates h, which is a fixed label. (uses petlib's hash_to_point)
        h_generators.append(h_i) # 

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

def hash_to_zq(data):
    """Cryptographically secure hash to Zq"""
    hasher = hashlib.sha256()
    hasher.update(str(data).encode())
    return Bn.from_binary(hasher.digest())

# genproof AI
def GenProof_ai(e, e_prime, r_prime, ψ, pk):
    """
    Generate shuffle proof for public anonymized keys
    
    Args:
        e: List of original public keys [pk1, pk2, ..., pkN]
        e_prime: List of shuffled & re-randomized public keys
        r_prime: Re-randomization values
        ψ: Permutation
        pk: Base public key (generator g)
    """
    _, g, order = gen.pp
    N = len(e)
    q = order

    # Step 1: Commit to permutation
    c, r = GenCommitment(ψ)

    # Step 2-7: Generate challenges and commitments
    u = []
    for i in range(N):
        u_i = hash_to_zq((str(e), str(e_prime), str(c), i))
        u.append(u_i)

    # Step 3: Permute challenges to get u_prime
    u_prime = []
    for i in range(N):
        u_prime.append(u[ψ[i]])
        
    # in genCommitmentChain h is c0
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
    r_prime_sum = sum((r_prime[i] * u_prime[i]) % q for i in range(N)) % q

    # Step 15-25: Generate witnesses and t-values
    w = [order.random() for _ in range(4)]
    w_hat = [order.random() for _ in range(N)]
    w_prime = [order.random() for _ in range(N)]

    t1 = g.pt_mul(w[0])
    t2 = g.pt_mul(w[1])
    
    t3 = g.pt_mul(w[2])
    for i in range(N):
        t3 = t3.pt_add(h_generators[i].pt_mul(w_prime[i])) # TODO Make sure that h_generators is actually populated
    
    # normally this step is for ElGamal pairs
    # we have an anonymized list of public keys so its simpler
    t4 = g.pt_mul(-w[3]) # Start with -ω4 * g

    for i in range(N):
        # e_prime[i] is a single EC point
        t4 = t4.pt_add(e_prime[i].pt_mul(w_prime[i]))

    t_hat = []
    for i in range(N):
        prev_c = h if i == 0 else c_hat[i-1]
        hat_t_i = g.pt_mul(w_hat[i]).pt_add(prev_c.pt_mul(w_prime[i]))
        t_hat.append(hat_t_i)

    # Step 26-27: Compute challenge
    y = (str(e), str(e_prime), str(c), str(c_hat), str(pk))
    t = (str(t1), str(t2), str(t3), str((t4)), str(t_hat))
    challenge = hash_to_zq((y, t))

    # Step 28-33: Compute responses
    s1 = (w[0] + challenge * r_bar) % q
    s2 = (w[1] + challenge * r_hat_sum) % q
    s3 = (w[2] + challenge * r_tilde) % q
    s4 = (w[3] + challenge * r_prime_sum) % q

    s_hat = [(w_hat[i] + challenge * r_hat[i]) % q for i in range(N)]
    s_prime = [(w_prime[i] + challenge * u_prime[i]) % q for i in range(N)]

    # Return only the proof π = (t, s, c, ĉ)
    proof = {
        't': (t1, t2, t3, t4, t_hat),
        's': (s1, s2, s3, s4, s_hat, s_prime),
        'c': c,
        'c_hat': c_hat,
        'h': h  # Needed for verification
    }

    return proof

def test_shuffle_proof():
    _, g, order = gen.pp
    N = 5
    # Generate test public keys (as EC points)
    e = [g.pt_mul(order.random()) for _ in range(N)]

    # Shuffle and re-randomize
    e_prime, r_prime, ψ = GenShuffle(e, g)

    # Generate proof using the AI version
    proof = GenProof_ai(e, e_prime, r_prime, ψ, g)

    print("Shuffle proof generated:")
    print(proof)

test_shuffle_proof()
# Algorithm 4.6: Checks the correctness of a shuffle proof π generated by Algo-
# rithm 4.3. The public values are the ElGamal encryptions e and e′ and the public
# encryption key pk.
def CheckProof():
    return ""
