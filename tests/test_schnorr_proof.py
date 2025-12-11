from utils.procedures import Procedures
import utils.signature as Sig
import utils.schnorr_priv_key_proof as schnorr_priv_key_proof

# test with NIZPKP
def test():
    pro = Procedures()
    params = pro.pub_param()
    sk, pk = Sig.key_gen(params[0]._name)

    # Schnorr signature
    msg = "hello signature"
    signature = Sig.schnorr_sign(sk, params, msg)
    print("Signature (R, s):", signature)
    is_valid = Sig.schnorr_verify(pk, params, msg, signature)
    print("Signature valid?", is_valid)

    # Schnorr NIZKP
    msg_zkp = "hello proof"
    proof = schnorr_priv_key_proof.schnorr_NIZKP_proof(pk, params, sk, msg_zkp)
    print("Proof (c, r, W):", proof)
    proof_valid = schnorr_priv_key_proof.schnorr_NIZKP_verify(pk, params, proof, msg_zkp)
    print("Proof valid?", proof_valid)

if __name__ == "__main__":
    test()