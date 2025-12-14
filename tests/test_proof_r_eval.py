from src.utils.eval import Eval       
from src.utils.procedures import Procedures

# test has been made with help from ai
def run_check():
    print("========================================")
    print("   Running Manual Check for Proof R")
    print("========================================\n")

    # 1. SETUP SYSTEM
    print("[1] Setting up System keys...")
    procs = Procedures()
    
    # Generate DSO keypair (Standard ElGamal)
    # Returns: ((ek, pp, proof), dk)
    dso_ek_struct, dso_dk = procs.ekey_gen_single()
    
    # Initialize Eval with the public key structure
    evaluator = Eval(dso_ek_struct)
    
    # Access the internal ElGamal instance for encryption helpers
    elgamal = procs.ahe
    ek = dso_ek_struct[0] # The actual encryption key point
    pp = dso_ek_struct[1] # Public parameters
    
    print("    System ready.\n")

    # 2. CREATE TEST DATA (Sum == Target)
    print("[2] Creating Encrypted Data (Sum = 100, Target = 100)...")
    val = 100
    
    # Encrypt Sum
    ct_sum = elgamal.encrypt_single(ek, val)
    
    # Encrypt Target (as a list, since epet expects a list of ciphertexts)
    ct_target = elgamal.encrypt_single(ek, val)
    ct_target_list = [ct_target]

    print("    Encryption done.\n")

    # 3. RUN EPET (Generates Proof)
    print("[3] Running EPET (Generating Proof)...")
    # This calls proof_r internally
    ct_eq, proof = evaluator.epet(ct_sum, ct_target_list)
    
    print(f"    Proof generated.")
    print(f"    - Challenge: {proof[2]}")
    print(f"    - Response:  {proof[1]}")
    print(f"    - Commitment (A) count: {len(proof[0])}\n")

    # 4. VERIFY PROOF (Should Pass)
    print("[4] Verifying Proof (Expected: True)...")
    result_valid = evaluator.verify_r(ct_sum, ct_target_list, ct_eq, proof)
    
    if result_valid:
        print("    ✅ SUCCESS: Valid proof verified correctly.")
    else:
        print("    ❌ FAILURE: Valid proof was rejected.")
    print("")

    # 5. TAMPER TEST (Should Fail)
    print("[5] Running Tamper Test (Expected: False)...")
    
    # Unpack the proof
    A_values, response, challenge = proof
    order = pp[2] # Extract order from params
    
    # Tamper with the response (add 1)
    fake_response = (int(response) + 1) % int(order)
    fake_proof = (A_values, fake_response, challenge)
    
    print(f"    Tampering: Changed response {response} -> {fake_response}")
    
    result_tampered = evaluator.verify_r(ct_sum, ct_target_list, ct_eq, fake_proof)
    
    if not result_tampered:
        print("    ✅ SUCCESS: Tampered proof was correctly rejected.")
    else:
        print("    ❌ FAILURE: Tampered proof was accepted (This is bad).")
    print("")

    # 6. DECRYPTION CHECK
    print("[6] Checking Decryption of Result (Expected: 0)...")
    # Decrypt the first ciphertext in the result list
    c1_eq, c2_eq = ct_eq[0]
    
    # Note: Depending on your library, this returns 0 (int) or Identity Point
    decrypted_point = elgamal.decrypt_single(dso_dk, (c1_eq, c2_eq))

    # Check if the result is the identity point (Zero)
    # In ECC, the identity point usually has x=None, y=None or behaves like 0
    identity_point = 0 * pp[1]  # 0 * Generator

    if decrypted_point == identity_point:
        print("    ✅ SUCCESS: Result decrypts to Identity Point (Match found).")
    else:
        print(f"    ⚠️ NOTE: Result is {decrypted_point}. If this isn't 0, verify logic.")

    print("\n========================================")
    print("           Check Complete")
    print("========================================")

if __name__ == "__main__":
    run_check()