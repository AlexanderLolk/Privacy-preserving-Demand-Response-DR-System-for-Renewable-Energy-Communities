import hashlib
import random
import threshold_crypto as tc

class Shuffle:
    """
    Implements a Verifiable Shuffle for Elliptic Curve points (e.g., Public Keys or Ciphertexts).
    
    This class allows a server to:
    1. Take a list of inputs (e).
    2. Permute (shuffle) them to hide their order.
    3. Re-randomize (blind) them so they look different.
    4. Generate a Zero-Knowledge Proof (ZKP) that the output is a valid shuffle of the input,
       without revealing the permutation mapping.

    References:
    - Code inspired by https://github.com/hyperion-voting/hyperion/blob/main/subroutines.py#L586
    - Algorithms based on "Pseudo-Code Algorithms for Verifiable Re-Encryption Mix-Nets" (Haenni, Locher, Koenig, Dubuis, 2017).
    """
    def __init__(self, pp):
        (self.curve, self.g, self.order) = pp
    
    def get_h_generators(self, N):
        """ 
        Generates a list of N independent generators (h_1, ..., h_N).
        These are used for Pedersen commitments to the permutation matrix.
        
        Args:
            N (int): Number of generators needed (equal to number of items to shuffle).
            
        Returns:
            list: List of ECC points.
        """
        h_generators_local = []
        
        for i in range(N):
            h_scalar = tc.number.random_in_range(1, self.order)
            h_i_point = int(h_scalar) * self.g
            h_generators_local.append(h_i_point)
        
        return h_generators_local
    
    def _serialize(self, data):
        """
        Recursively serialize data to a canonical string format for hashing.
        """
        if isinstance(data, list) or isinstance(data, tuple):
            return "[" + ",".join(self._serialize(x) for x in data) + "]"
        elif hasattr(data, 'x') and hasattr(data, 'y'):
            # It's an EccPoint, serialize coordinates
            return f"({int(data.x)},{int(data.y)})"
        else:
            # Integers, strings, etc.
            return str(data)
        
    def hash_to_zq(self, data):
        """ 
        Hash generic data to a scalar in the field Z_q (modulo curve order).
        Used to generate non-interactive challenges (Fiat-Shamir heuristic).
        """
        # Use canonical serialization
        serialized_data = self._serialize(data)
        
        hasher = hashlib.sha256()
        hasher.update(serialized_data.encode())
        digest = hasher.digest()
        return int.from_bytes(digest, "big")   

    def GenPermutation(self, N):
        """ 
        Generates a random permutation vector of size N.
        
        Returns:
            list: A list of indices [0, 1, ..., N-1] in random order.
        """
        I = list(range(N))
        j_i = list(range(N))
        for i in range(N):
            k = random.randint(i, N-1)
            j_i[i] = I[k]
            I[k] = I[i]
        return j_i

    def GenShuffle(self, e):
        """ 
        Performs the actual Shuffle and Re-randomization.
        
        Given input list e, it computes e' such that:
        e'[i] = e[ψ[i]] + r[i]*G
        
        Args:
            e (list): List of input points (public keys or ciphertexts).
            
        Returns:
            tuple: (shuffled_list, randomness_list, permutation_indices)
        """
        N = len(e)
        ψ = self.GenPermutation(N)
        
        r_prime = []
        e_prime = []

        for i in range(N):
            r_i = tc.number.random_in_range(1, self.order)
            r_prime.append(r_i)

            # Additive blinding e[i] + r_i * G
            blinding_factor = int(r_i) * self.g
            pk_prime = e[i] + blinding_factor

            e_prime.append(pk_prime)

        # shuffle it
        e_prime_shuffled = [e_prime[ψ[j]] for j in range(N)]
        return (e_prime_shuffled, r_prime, ψ)

    def GenCommitment(self, ψ, h_gens):
        """ 
        Commits to the permutation matrix.
        
        This uses Pedersen commitments. Specifically, it commits to the fact that
        the permutation maps index i to j.
        
        Args:
            ψ (list): The permutation vector.
            h_gens (list): Independent generators.
            
        Returns:
            tuple: (commitments_c, randomness_r)
        """

        N = len(ψ)
        
        # Pre-allocate list
        c = [None] * N 
        r = []

        # Generate randomness for all N commitments
        for _ in range(N):
            r.append(tc.number.random_in_range(1, self.order))

        for i in range(N):
            j = ψ[i]
            
            # c[j] = r[j] * G + h_gens[i]
            h_term = h_gens[i]
            g_term = int(r[j]) * self.g
            c[j] = h_term + g_term

        return (c, r)

    def GenCommitmentChain(self, c0, u):
        """ 
        Generates a chain of commitments, used for the proof to verify the permutation structure without revealing it.
        """
        N = len(u)
        c = []
        r = []

        for i in range(N):
            r_i = tc.number.random_in_range(1, self.order)
            r.append(r_i)
            
            if i == 0:
                prev_c = c0
            else:
                prev_c = c[i - 1]
            
            # c_i = r_i * g + u_i * c_{i-1}
            # This recursive structure binds the current commitment to the previous one
            c_i = (int(r_i) * self.g) + (int(u[i]) * prev_c)
            c.append(c_i)

            prev_c = c_i
        
        return (c, r)

    # pk for ours is ek
    def GenProof(self, e, e_prime, r_prime, ψ, expo):
        """ 
        Generates a non-interactive Zero-Knowledge Proof (ZKP) of the shuffle.
        
        This proves:
        1. e_prime is a permutation of e.
        2. e_prime is a re-randomization of e (knowing the discrete logs r_prime).
        
        Args:
            e (list): Original inputs.
            e_prime (list): Shuffled outputs.
            r_prime (list): Randomness used for blinding.
            ψ (list): Permutation used.
            expo: exponent g.

        Returns:
            dict: The proof structure containing commitments (t), responses (s), and helper values.
        """
        N = len(e)
        q = int(self.order)

        # get h
        h_gens = self.get_h_generators(N)

        # Commit to permutation
        c, r = self.GenCommitment(ψ, h_gens)

        # Generate challenges
        u = []
        for i in range(N):
            u_i = self.hash_to_zq((e, e_prime, c, i)) 
            u.append(u_i)

        u_prime = [u[ψ[j]] for j in range(N)]
            
        # GenCommitmentChain
        h_scalar = tc.number.random_in_range(1, self.order)
        h = int(h_scalar) * self.g
        c_hat, r_hat = self.GenCommitmentChain(h, u_prime)

        # Compute weighted sums
        r_bar = sum(int(r_val) for r_val in r) % q

        v = [0] * N
        v[N-1] = 1
        for i in range(N-2, -1, -1):
            v[i] = (int(u_prime[i+1]) * v[i+1]) % q
        
        r_hat_sum = sum((int(r_hat[i]) * v[i]) % q for i in range(N)) % q
        r_tilde = sum((int(r[i]) * int(u[i])) % q for i in range(N)) % q
        r_prime_sum = sum((int(r_prime[i]) * int(u[i])) % q for i in range(N)) % q

        # Generate witnesses
        w = [tc.number.random_in_range(1, self.order) for _ in range(4)]
        w_hat = [tc.number.random_in_range(1, self.order) for _ in range(N)]
        w_prime = [tc.number.random_in_range(1, self.order) for _ in range(N)]

        # t-values (commitments)
        t1 = int(w[0]) * self.g
        t2 = int(w[1]) * self.g
        t3 = int(w[2]) * self.g
        for i in range(N):
            t3 = t3 + (int(w_prime[i]) * h_gens[i])
        
        # t4 = Σ(w'_i * e'_i) - w[3] * G
        sum_w_prime_e_prime = int(w_prime[0]) * e_prime[0]
        for i in range(1, N):
            sum_w_prime_e_prime = sum_w_prime_e_prime + (int(w_prime[i]) * e_prime[i])
        
        w3_g = int(w[3]) * self.g
        t4 = sum_w_prime_e_prime + (-w3_g)

        t_hat = []
        for i in range(N):
            if i == 0:
                prev_c = h
            else:
                prev_c = c_hat[i-1]
            
            hat_t_i = (int(w_hat[i]) * self.g) + (int(w_prime[i]) * prev_c)
            t_hat.append(hat_t_i)
        
        # Compute challenge
        y = (e, e_prime, c, c_hat, expo)
        t = (t1, t2, t3, t4, t_hat)
        challenge = self.hash_to_zq((y, t))

        # Compute responses
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

    def verify_shuffle_proof(self, proof, e, e_prime, expo):
        """ 
        Verifies the Zero-Knowledge Proof of Shuffle.
        
        Reconstructs the commitments from the responses and checks if they match 
        the challenges.

        Args:
            proof (dict): The proof object generated by GenProof.
            e (list): The original input list.
            e_prime (list): The shuffled output list.
            expo: Public parameter.

        Returns:
            bool: True if proof is valid, False otherwise.
        """
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
            u_i = self.hash_to_zq((e, e_prime, c, i))
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
            u_product = (u_product * int(u[i])) % int(self.order)
        
        # c_hat_final = c_hat[N-1] - u_product * h
        c_hat_final = c_hat[N-1] + (-(int(u_product) * h))
        
        # c_tilde = Σ(u_i * c_i)
        c_tilde = int(u[0]) * c[0]
        for i in range(1, N):
            c_tilde = c_tilde + (int(u[i]) * c[i])
        
        # Recomputing the challenge
        y = (e, e_prime, c, c_hat, expo)
        t = (t1, t2, t3, t4, t_hat)
        challenge = self.hash_to_zq((y, t))
        
        # Verify t1 = -challenge*c_bar + s1*g
        t1_prime = (-(int(challenge) * c_bar)) + (int(s1) * self.g)
        t1_check = (t1 == t1_prime)
        
        # Verify t2 = -challenge*c_hat_final + s2*g
        t2_prime = (-(int(challenge) * c_hat_final)) + (int(s2) * self.g)
        t2_check = (t2 == t2_prime)
        
        # Verify t3
        t3_prime_1 = -(int(challenge) * c_tilde)
        t3_prime_2 = int(s3) * self.g
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
        term_s4 = int(s4) * self.g
        
        t4_prime = sum_s_prime_e_prime + (-term_challenge) + (-term_s4)
        t4_check = (t4 == t4_prime)

        # Verify t_hat chain
        t_hat_valid = True
        for i in range(N):
            if i == 0:
                prev_c = h
            else:
                prev_c = c_hat[i-1]
            
            t_hat_prime = (-(int(challenge) * c_hat[i])) + (int(s_hat[i]) * self.g) + (int(s_prime[i]) * prev_c)
            
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