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
import utils.signature as sig
import utils.NIZKP as nizkp

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
    sk, pk = sig.key_gen(pp)
    proof =  nizkp.schnorr_NIZKP_proof(pp, pk, sk)
    
    return ((id, (pk, pp, proof)), sk)