# SKeyGen(id, pp) → ((id, pk), sk):

# On input identity id and pp executes (sk, pk) ← Sig.KeyGen(1λ, id)
# to generate signature key pair (sk, pk).

# It computes πsk ← Proofsk((id, pp, pk), sk) and updates
# pk such that pk contains pp and a proof of knowledge πsk, and returns ((id, pk), sk).

# 1^lambda = sec_params

# TODO
# integrate non-interactive proof of zero knowledge (NIZKPK) for the secret key sk corresponding to pk


from petlib.ec import EcGroup
import random
import utils.signature as Sig
import utils.NIZKP as NIZKP

def pub_param(nid=713):
    group_G = EcGroup()
    g = group_G.generator()
    order = group_G.order()
    return (group_G, g, order)

# SKey_Gen(id, pp) → ((id, pk), sk)
# generates signature key pair (sk, pk) for identity id
def skey_gen(id=random, pp=None):
    if pp is None:
        pp = pub_param()
    sk, pk = Sig.key_gen(pp)
    return ((id, pk), sk)


# test with NIZPKP
def test():
    params = pub_param()
    sk, pk = Sig.key_gen(params)

    # Schnorr signature
    msg = "hello signature"
    signature = Sig.schnorr_sign(params, sk, msg)
    print("Signature (R, s):", signature)
    is_valid = Sig.schnorr_verify(params, pk, msg, signature)
    print("Signature valid?", is_valid)

    # Schnorr NIZKP
    msg_zkp = "hello proof"
    proof = NIZKP.schnorr_proof(params, pk, sk, msg_zkp)
    print("Proof (c, r, W):", proof)
    proof_valid = NIZKP.schnorr_NIZKP_verify(params, pk, proof, msg_zkp)
    print("Proof valid?", proof_valid)

if __name__ == "__main__":
    test()