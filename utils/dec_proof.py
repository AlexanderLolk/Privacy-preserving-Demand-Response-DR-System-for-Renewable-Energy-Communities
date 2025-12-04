# from petlib.ec import EcGroup, EcPt
# from petlib.bn import Bn
# from utils.ec_elgamal import ElGamal #, dec, make_table
# import hashlib
# import threshold_crypto as tc

# def hash_to_bn(*points, order):
#     """Hash EC points deterministically into a scalar mod q."""
#     h = hashlib.sha256()
#     for P in points:
#         if hasattr(P, "point"):
#             P = P.point
#         if hasattr(P, "x") and hasattr(P, "y"):
#             h.update(int(P.x).to_bytes(32, "big"))
#             h.update(int(P.y).to_bytes(32, "big"))
#         else:
#             h.update(str(P).encode())
#     return int.from_bytes(h.digest(), "big") % order

# def prove_correct_decryption(ek, sec_params, M, dk):
#     """Prove that M = C2 - dk * C1 (i.e., correct ElGamal decryption)
#     without revealing dk.
#     Returns a non-interactive proof (A1, A2, s).

#     Args:
#         ek (EcPt): ElGamal public key point (ek = x * g).
#         sec_params (tuple): Triple (EcGroup, generator g (EcPt), order (Bn)).
#         M (EcPt|Bn|int): Message encoded as an EC point or a scalar.
#         dk (Bn): Secret key scalar corresponding to `ek`.

#     Returns:
#         tuple: (M_point, CT, (A1, A2), s)
#             - M_point (EcPt): the message as an EC point
#             - CT (tuple): ciphertext pair (C1, C2)
#             - (A1, A2) (tuple): commitment points
#             - s (Bn): response scalar for the NIZK
#     """
#     g = sec_params.P
#     order = sec_params.order
#     CT = ElGamal.enc(ek, sec_params, M)
#     ct_0 = CT.C1
#     ct_1 = CT.C2

#     if hasattr(M, "x") and hasattr(M, "y"):
#         M_point = M
#     elif isinstance(M, int):
#         M_point = g * M
#     else:
#         M_point = g * int(M)

#     r = int(tc.number.random_in_range(1, order))       # random nonce

#     # A1 = r * g      # commitment of ciphertext 1
#     # A2 = r * C1     # commitment of ciphertext 2
#     commitment_ct_0 = g * r    # commitment of ciphertext 1
#     commitment_ct_1 = ct_0 * r     # commitment of ciphertext 2
#     commitment_CT = (commitment_ct_0, commitment_ct_1)

#     # V = C2 - M
#     V = ct_1 + (-M_point)
    
#     challenge = hash_to_bn(g, ek, ct_0, ct_1, M_point, V, commitment_ct_0, commitment_ct_1, order=order)
#     # s = r + c * dk % order
#     # Ensure dk is an integer
#     if isinstance(dk, list):
#         dk = dk[0]
#     if hasattr(dk, "d"):
#         dk = int(dk.d)
#     else:
#         dk = int(dk)
#     response = (r + challenge * dk) % order

#     return (M_point, CT, commitment_CT, response)

# def verify_correct_decryption(ek, sec_params, proof):
#     """Verify a Chaum–Pedersen style NIZK proof of correct decryption.

#     Args:
#         ek (EcPt): ElGamal public key point.
#         sec_params (tuple): Triple (EcGroup, generator g (EcPt), order (Bn)).
#         proof (tuple): Proof returned by `prove_correct_decryption`.

#     Returns:
#         bool: True if the proof verifies, False otherwise.
#     """
#     _, g, order = sec_params
#     M, CT, commitment_CT, s = proof
#     ct_0, ct_1 = CT
#     commitment_ct_0, commitment_ct_1 = commitment_CT
    
#     if isinstance(M, EcPt):
#         M_point = M
#     elif isinstance(M, Bn):
#         M_point = g.pt_mul(M)
#     else:
#         M_point = g.pt_mul(Bn(M))

#     # V = C2 - M         
#     # V = C2.pt_add(M.pt_neg()) 
#     V = ct_1.pt_add(M_point.pt_neg()) 
#     # V = C2.pt_add(Bn(M).int_neg())
#     # V = C2 + (Bn(M).int_mul(Bn(-1)))
    
#     # C2 = M + order * ek
#     # C2 = M + order * x * g
#     # C2 - M = order * x * g
#     # C2 - M = x * order * g
#     # C2 - M = x * C1

#     c = hash_to_bn(g, ek, ct_0, ct_1, M_point, V, commitment_ct_0, commitment_ct_1, order=order)

#     #  check1 = (s * g == A1 + c * ek)
#     check1 = (g.pt_mul(s) == commitment_ct_0.pt_add(ek.pt_mul(c)))

#     # check2 = (s * C1 == A2 + c * V)
#     # check2 = (C1.pt_mul(s) == A2.pt_add(V.pt_mul(c)))
#     check2 = (ct_0.pt_mul(s) == commitment_ct_1.pt_add(c * V))

#     return check1 and check2

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