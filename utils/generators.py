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
import utils.ec_elgamal as ahe

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

# EKeyGen(pp) → (ek, dk): On input of the public parameter pp, executes (ek, dk) ← AHE.KeyGen(1λ)
# which outputs encryption key pair.
# It then computes πdk ← Proofdk((pp, ek), dk), updates ek such
# that ek contains pp along with πdk, and returns (ek, dk).
def ekey_gen(pp=None):
    if pp is None:
        pp = pub_param()
    ek, dk = ahe.key_gen(pp)
    πdk = nizkp.schnorr_NIZKP_proof(pp, ek, dk)
    return ((ek, pp, πdk), dk)

# MixID(pk) → (pk′, r′, πmix): On input set IDpk = {(id, pk)}id∈ID computes shuffle and ran-
# domization to generate the mixed public key set pk′ = {pk′1, pk′2, ... , pk′n} where n = |ID|. It
# also computes πmix $ ← Proofmix((pk, pk′), ωmix), where πmix denotes the proof of knowledge of
# the correct mixing. The ωmix denotes the knowledge of secret shuffle and randomization.(here
# needs signature and different randomness r for each pki the user gets gr′
# not r′)

# to be reworked
def mix_id(pk_list):

    # shuffle
    pk_shuffled = pk_list.copy()
    random.shuffle(pk_shuffled)
    
    # randomize
    pk_mixed = []
    r_list = [] # list of randomness for each pk

    for id_val, (pk, pp, proof) in pk_shuffled:
        _, g, order = pp
        ωmix = order.random() 
        pk_mark = pk + ωmix * g # randomize by adding ωmix * g so pk′ = pk + ωmix·g
        pk_mixed.append((id_val, (pk_mark, pp, proof)))
        r_list.append(ωmix)

    πmix = nizkp.schnorr_NIZKP_proof(pp, pk_mark, ωmix) # not the correct proof?

    return (pk_mixed, r_list, πmix)

# print("mix", mix_id([("id1", skey_gen("id1")[0][1]), ("id2", skey_gen("id2")[0][1]) ]))

# Report(id, sk, ek, m, t) → (pk, (t, ct, σ)): on input smart meter identity id ∈ ID, secret signing
# key sk, servers public encryption key ek, smart meter data m ∈ M, and timestamp t does the following:
# 1. Compute mbin = (m1, m2, ... , mb) which is a binary form of m.
# 2. Compute cti $ ←− AHE.Enc(ek,mi; ri) for each mi ∈ (m1, m2, ... , mb).
# 3. Set ct = (ct1, ct2, ... , ctb) where ct is a list of encryptions of the binary representation of energy consumption m.
# 4. Compute σ $ ←− Sig.Sign(sk, (t, ct)).
# 5. Return (pk, (t, ct, σ)).

def report(id, sk, ek, m, t):
    return ""