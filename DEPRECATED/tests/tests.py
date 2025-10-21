import utils.generators as gen
import utils.signature as Sig
import utils.NIZKP as NIZKP

# test with NIZPKP
def test():
    params = gen.pub_param()
    sk, pk = Sig.key_gen(params)

    # Schnorr signature
    msg = "hello signature"
    signature = Sig.schnorr_sign(params, sk, msg)
    print("Signature (R, s):", signature)
    is_valid = Sig.schnorr_verify(params, pk, msg, signature)
    print("Signature valid?", is_valid)

    # Schnorr NIZKP
    msg_zkp = "hello proof"
    proof = NIZKP.schnorr_NIZKP_proof(params, pk, sk, msg_zkp)
    print("Proof (c, r, W):", proof)
    proof_valid = NIZKP.schnorr_NIZKP_verify(params, pk, proof, msg_zkp)
    print("Proof valid?", proof_valid)

if __name__ == "__main__":
    test()