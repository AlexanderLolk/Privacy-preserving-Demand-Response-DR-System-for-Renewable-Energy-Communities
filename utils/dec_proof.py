from utils.ec_elgamal import ElGamal
import hashlib
import threshold_crypto as tc

def hash_to_bn(*points, order):
    """Hash EC points deterministically into a scalar mod q."""
    h = hashlib.sha256()
    for P in points:
        if hasattr(P, "x") and hasattr(P, "y"):
            h.update(int(P.x).to_bytes(32, "big"))
            h.update(int(P.y).to_bytes(32, "big"))
        else:
            h.update(str(P).encode())
    return int.from_bytes(h.digest(), "big") % int(order)

def prove_correct_decryption(ek, pp, M, dk, ciphertext):
    """Prove that M = C2 - dk * C1 (i.e., correct ElGamal decryption)
    without revealing dk.
    Returns a non-interactive proof (A1, A2, s).

    Args:
        ek (ECC Point): ElGamal public key point (ek = dk * g).
        sec_params (tc.CurveParameters): Curve parameters.
        M (int): Message as an integer.
        dk (int): Secret key scalar corresponding to `ek`.
        ciphertext (tuple): (C1, C2) ElGamal ciphertext pair.

    Returns:
        tuple: (M_point, CT, (A1, A2), s)
            - M_point (ECC Point): the message as an EC point
            - CT (tuple): ciphertext pair (C1, C2)
            - (A1, A2) (tuple): commitment points
            - s (int): response scalar for the NIZK
    """
    
    # Extract ciphertext components
    ct_0, ct_1 = ciphertext

    # Convert message to point
    if isinstance(M, int):
        M_point = int(M) * pp[1]
    else:
        M_point = M

    r = tc.number.random_in_range(1, pp[2])  # random nonce

    # A1 = r * g, A2 = r * C1
    commitment_ct_0 = int(r) * pp[1]
    commitment_ct_1 = int(r) * ct_0
    commitment_CT = (commitment_ct_0, commitment_ct_1)

    # V = C2 - M
    V = ct_1 + (-M_point)
    
    challenge = hash_to_bn(pp[1], ek, ct_0, ct_1, M_point, V, commitment_ct_0, commitment_ct_1, order=pp[2])
    
    # Ensure dk is an integer
    if isinstance(dk, list):
        dk = dk[0]
    # if hasattr(dk, "d"):
    #     dk = int(dk.d)
    else:
        dk = int(dk)
    
    response = (int(r) + int(challenge) * dk) % pp[2]

    return (M_point, ciphertext, commitment_CT, response)

def verify_correct_decryption(ek, pp, proof):
    """Verify a Chaum–Pedersen style NIZK proof of correct decryption.

    Args:
        ek (ECC Point): ElGamal public key point.
        sec_params (tc.CurveParameters): Curve parameters.
        proof (tuple): Proof returned by `prove_correct_decryption`.

    Returns:
        bool: True if the proof verifies, False otherwise.
    """
    
    M, CT, commitment_CT, s = proof
    ct_0, ct_1 = CT
    commitment_ct_0, commitment_ct_1 = commitment_CT
    
    # Convert M to point if needed
    if isinstance(M, int):
        M_point = int(M) * pp[1]
    else:
        M_point = M

    # V = C2 - M
    V = ct_1 + (-M_point)
    
    c = hash_to_bn(pp[1], ek, ct_0, ct_1, M_point, V, commitment_ct_0, commitment_ct_1, order=pp[2])

    # check1: s * g == A1 + c * ek
    check1 = (int(s) * pp[1] == commitment_ct_0 + (int(c) * ek))

    # check2: s * C1 == A2 + c * V
    check2 = (int(s) * ct_0 == commitment_ct_1 + (int(c) * V))

    return check1 and check2


# def prove_correct_threshold_decryption(ek, pp, M, partial_decryptions, ciphertext, key_shares=None):
#     """Prove via Chaum–Pedersen NIZK that each partial decryption is correct,
#     and that their Lagrange-weighted sum equals C2 - M.

#     For each key share, generates a Chaum–Pedersen proof showing:
#       share_pub = y * g  and  yC1 = y * C1
#     where y is the share secret and yC1 is the partial decryption.

#     Then verifies the combined (Lagrange-weighted) partials equal C2 - M.

#     Args:
#         ek (ECC Point): Threshold public key.
#         pp (tuple): (curve, g, order)
#         M (int): Message as an integer.
#         partial_decryptions (list): List of tc.PartialDecryption objects.
#         ciphertext (tuple): (C1, C2) ElGamal ciphertext pair.
#         key_shares (list): List of tc.KeyShare objects (needed to access share secrets).

#     Returns:
#         tuple: (M_point, ciphertext, per_share_proofs, accumulated_point)
#             where per_share_proofs is a list of (share_index, yC1, share_pub, (A1, A2), s)
#             for each share (Chaum–Pedersen proof structure with public share point).
#     """

#     # If ciphertext is a single tuple, keep the earlier single-ciphertext behavior
#     if not isinstance(ciphertext, list):
#         ct_0, ct_1 = ciphertext

#         # Convert message to point if needed
#         if isinstance(M, int):
#             M_point = int(M) * pp[1]
#         else:
#             M_point = M

#         # Gather indices
#         partial_indices = [pd.x for pd in partial_decryptions]

#         # Compute Lagrange coefficients
#         lagrange_coefficients = [
#             tc.lagrange_coefficient_for_key_share_indices(partial_indices, idx, pp[0])
#             for idx in partial_indices
#         ]

#         # Generate per-share Chaum–Pedersen proofs
#         per_share_proofs = []
#         for i, pd in enumerate(partial_decryptions):
#             share_idx = pd.x
#             yC1 = pd.yC1

#             # Find the key share with matching index
#             if key_shares is not None:
#                 share_y = None
#                 for ks in key_shares:
#                     if ks.x == share_idx:
#                         share_y = ks.y
#                         break

#                 if share_y is None:
#                     raise ValueError(f"No key share found with index {share_idx}")
#             else:
#                 raise ValueError("key_shares must be provided to generate threshold proof")

#             # Compute share's public value
#             share_pub = share_y * pp[1]

#             # Chaum–Pedersen proof for y: show share_pub = y*g and yC1 = y*C1
#             r = tc.number.random_in_range(1, pp[2])

#             # Commitments: A1 = r*g, A2 = r*C1
#             A1 = int(r) * pp[1]
#             A2 = int(r) * ct_0

#             # Fiat–Shamir challenge (include share_pub)
#             c = hash_to_bn(pp[1], ct_0, share_pub, yC1, A1, A2, order=pp[2])

#             # Response: s = r + c*y (mod q)
#             s = (int(r) + int(c) * int(share_y)) % pp[2]

#             # Store proof: (share_index, yC1, share_pub, (A1, A2), s)
#             per_share_proofs.append((share_idx, yC1, share_pub, (A1, A2), s))

#         # Compute accumulated point (Lagrange-weighted sum)
#         summands = [
#             (lagrange_coefficients[i].coefficient * partial_decryptions[i].yC1)
#             for i in range(len(partial_decryptions))
#         ]
#         accumulated_point = tc.number.ecc_sum(summands)

#         # Return proof tuple
#         return (M_point, ciphertext, per_share_proofs, accumulated_point)

#     # Otherwise handle bitwise ciphertexts (list of (c1,c2))
#     # partial_decryptions is expected to be a list of lists: per-share partials
#     # where partial_decryptions[j][i] is the PartialDecryption from share j for bit i.
#     ciphertexts = ciphertext

#     # Determine bit-length from ciphertexts
#     num_bits = len(ciphertexts)

#     # Convert M to bit list with fixed length
#     def int_to_bits_with_length(value, length):
#         bits = [(value >> i) & 1 for i in range(length)]
#         # bits currently little-endian (LSB first); reverse to match enc order
#         bits = list(reversed(bits))
#         return bits

#     if isinstance(M, int):
#         bits = int_to_bits_with_length(M, num_bits)
#     else:
#         # If M provided as list of bits or points, try to adapt
#         try:
#             bits = [int(b) for b in M]
#         except Exception:
#             raise ValueError("M must be integer or iterable of bits when using bitwise ciphertexts")

#     # Prepare per-bit proofs and accumulated points
#     per_bit_proofs = []
#     accumulated_points = []

#     # For each bit index i, generate per-share Chaum–Pedersen proofs
#     for i in range(num_bits):
#         c1_i, c2_i = ciphertexts[i]

#         # Collect per-share proofs for this bit
#         proofs_for_bit = []

#         # Gather partial indices for Lagrange
#         partial_indices = [partial_decryptions[j][i].x for j in range(len(partial_decryptions))]

#         # Compute Lagrange coefficients for this bit
#         lagrange_coeffs = [
#             tc.lagrange_coefficient_for_key_share_indices(partial_indices, idx, pp[0])
#             for idx in partial_indices
#         ]

#         # For each share
#         for j in range(len(partial_decryptions)):
#             pd = partial_decryptions[j][i]
#             share_idx = pd.x
#             yC1 = pd.yC1

#             # Find corresponding key share
#             if key_shares is not None:
#                 share_y = None
#                 for ks in key_shares:
#                     if ks.x == share_idx:
#                         share_y = ks.y
#                         break
#                 if share_y is None:
#                     raise ValueError(f"No key share found with index {share_idx}")
#             else:
#                 raise ValueError("key_shares must be provided to generate threshold proof for bitwise ciphertexts")

#             share_pub = share_y * pp[1]

#             r = tc.number.random_in_range(1, pp[2])
#             A1 = int(r) * pp[1]
#             A2 = int(r) * c1_i
#             c = hash_to_bn(pp[1], c1_i, share_pub, yC1, A1, A2, order=pp[2])
#             s = (int(r) + int(c) * int(share_y)) % pp[2]

#             proofs_for_bit.append((share_idx, yC1, share_pub, (A1, A2), s))

#         # Compute accumulated point for this bit
#         summands = [
#             (lagrange_coeffs[k].coefficient * partial_decryptions[k][i].yC1)
#             for k in range(len(partial_decryptions))
#         ]
#         accumulated = tc.number.ecc_sum(summands)

#         # Store
#         per_bit_proofs.append(proofs_for_bit)
#         accumulated_points.append(accumulated)

#     # Return proof structure for bitwise encryption
#     return (bits, ciphertexts, per_bit_proofs, accumulated_points)


# def verify_correct_threshold_decryption(ek, pp, proof, share_public_points=None):
#     # Detect whether this is the single-ciphertext form or bitwise form
#     first = proof[0]
#     # Single-ciphertext form: (M_point, (c1,c2), per_share_proofs, accumulated_point)
#     if not isinstance(first, list):
#         M_point, CT, per_share_proofs, accumulated_point = proof
#         ct_0, ct_1 = CT

#         # Convert M to point if needed
#         if isinstance(M_point, int):
#             M_point = int(M_point) * pp[1]

#         # Verify each per-share Chaum–Pedersen proof
#         for proof_item in per_share_proofs:
#             share_idx, yC1, share_pub, commitment_pair, s = proof_item
#             A1, A2 = commitment_pair

#             # Recompute Fiat–Shamir challenge
#             c = hash_to_bn(pp[1], ct_0, share_pub, yC1, A1, A2, order=pp[2])

#             # Check 1: s*g == A1 + c*share_pub
#             check1 = (int(s) * pp[1] == A1 + (int(c) * share_pub))

#             # Check 2: s*C1 == A2 + c*yC1
#             check2 = (int(s) * ct_0 == A2 + (int(c) * yC1))

#             if not (check1 and check2):
#                 return False

#         # Verify combined correctness: accumulated == C2 - M
#         V = ct_1 + (-M_point)
#         return accumulated_point == V

#     # Bitwise form: (bits, [ (c1,c2), ... ], per_bit_proofs, [accumulated_points...])
#     bits, ciphertexts, per_bit_proofs, accumulated_points = proof

#     num_bits = len(ciphertexts)
#     for i in range(num_bits):
#         c1_i, c2_i = ciphertexts[i]
#         proofs_for_bit = per_bit_proofs[i]
#         accumulated = accumulated_points[i]

#         # Verify each per-share proof for this bit
#         for proof_item in proofs_for_bit:
#             share_idx, yC1, share_pub, commitment_pair, s = proof_item
#             A1, A2 = commitment_pair

#             c = hash_to_bn(pp[1], c1_i, share_pub, yC1, A1, A2, order=pp[2])
#             check1 = (int(s) * pp[1] == A1 + (int(c) * share_pub))
#             check2 = (int(s) * c1_i == A2 + (int(c) * yC1))
#             if not (check1 and check2):
#                 return False

#         # Compute expected V = C2 - M_bit*g
#         bit = bits[i]
#         M_bit_point = int(bit) * pp[1]
#         V = c2_i + (-M_bit_point)

#         if accumulated != V:
#             return False

#     return True


# def test_threshold_dec_proof():
#     elgamal = ElGamal("P-256")
#     pub_key, key_shares, thresh_params = elgamal.keygen_threshold()

#     m = 7
#     # Use bitwise encryption
#     ciphertexts = elgamal.enc(pub_key, m)

#     # Each key share computes partial decryptions for all bits
#     partials_by_share = []
#     for ks in key_shares:
#         pd_list = elgamal.partial_decrypt(ciphertexts, ks)
#         partials_by_share.append(pd_list)

#     # Generate proof (with key_shares so we can compute per-share proofs)
#     print("\n3. Generating threshold decryption proof (bitwise, per-share Chaum–Pedersen)...")
#     proof = prove_correct_threshold_decryption(pub_key, elgamal.pp, m, partials_by_share, ciphertexts, key_shares=key_shares)
#     print("   Proof generated")

#     # Verify proof
#     print("\n4. Verifying threshold proof (bitwise)...")
#     is_valid = verify_correct_threshold_decryption(pub_key, elgamal.pp, proof)
#     print(f"   Valid: {is_valid}")
#     assert is_valid, "Threshold decryption proof verification failed!"

#     print("\n=== All threshold decryption proof tests passed! ===\n")


def test_dec_proof():
    """Test decryption proof generation and verification."""
    print("=== Testing Decryption Proof ===")
    
    # Setup
    elgamal = ElGamal("P-256")
    
    # Generate keypair
    print("1. Generating ElGamal keypair...")
    (ek, pp), dk = elgamal.keygen()
    print(f"   Secret key: {dk}")
    print(f"   Public key: {ek}")
    
    # Encrypt a message
    print("\n2. Encrypting message...")
    m = 42
    print(f"   Message: {m}")
    ciphertext = elgamal.encrypt_single(ek, m)
    print(f"   Ciphertext: {ciphertext}")
    
    # Generate proof
    print("\n3. Generating decryption proof...")
    proof = prove_correct_decryption(ek, pp, m, dk, ciphertext)
    print(f"   Proof generated")
    
    # Verify proof
    print("\n4. Verifying proof...")
    is_valid = verify_correct_decryption(ek, pp, proof)
    print(f"   Valid: {is_valid}")
    assert is_valid, "Decryption proof verification failed!"
    
    print("\n=== All decryption proof tests passed! ===\n")


if __name__ == "__main__":
    test_dec_proof()
    test_threshold_dec_proof()