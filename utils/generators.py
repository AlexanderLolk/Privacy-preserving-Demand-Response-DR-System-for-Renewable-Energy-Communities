from petlib.ec import EcGroup
import hashlib
import random
import utils.signature as sig
import utils.NIZKP as nizkp
import utils.ec_elgamal as ahe

def pub_param(nid=713):
    group_G = EcGroup()
    g = group_G.generator()
    order = group_G.order()
    return (group_G, g, order)

pp = pub_param()

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

# TODO to be reworked
def mix_id(pk_list):
    # shuffle
    pk_shuffled = pk_list.copy()
    random.shuffle(pk_shuffled) # TODO use a secret shuffle
    
    # lists and map
    pk_mixed = []
    r_map = {}
    proofs = []

    for id_val, (pk, pp, proof) in pk_shuffled:
        _, g, order = pp
        ωmix = order.random()
        pk_mark = pk + ωmix * g # randomize the key
        # compute difference and proof (pk_mark - pk = (pk + ωmix * g) - pk = ωmix * g)
        diff = pk_mark - pk
        πmix = nizkp.schnorr_NIZKP_proof(pp, diff, ωmix) # proof that can prove knowledge of ωmix
        pk_mixed.append((id_val, (pk_mark, pp, proof)))
        r_map[id_val] = ωmix
        proofs.append(πmix)

    # πmix could be a hash/signature of all proofs, or a Merkle root, etc.
    proof_bytes = b''.join([str(p).encode() for p in proofs])
    πmix_ = hashlib.sha256(proof_bytes).hexdigest()

    return (pk_mixed, r_map, proofs, πmix_)

# def verify_mix_id(pk_list, pk_mixed, r_map, proofs):
#     # Build a mapping from id to original pk and pp
#     pk_dict = {id_val: (pk, pp) for id_val, (pk, pp, _) in pk_list}
#     results = []
#     for i, (id_val, (pk_mark, pp, _)) in enumerate(pk_mixed):
#         pk, _pp = pk_dict[id_val]
#         ωmix = r_map[id_val]
#         πmix = proofs[i]
#         diff = pk_mark - pk
#         verified = nizkp.schnorr_NIZKP_verify(pp, diff, πmix)
#         results.append((id_val, verified))
#     return results


# pk_list = [("id1", skey_gen("id1")[0][1]), ("id2", skey_gen("id2")[0][1]), ("id3", skey_gen("id3")[0][1]), ("id4", skey_gen("id4")[0][1])]
# pk_mixed, r_map, proofs, πmix = mix_id(pk_list)
# print("verify", verify_mix_id(pk_list, pk_mixed, r_map, proofs))


# Report(id, sk, ek, m, t) → (pk, (t, ct, σ)): on input smart meter identity id ∈ ID, secret signing
# key sk, servers public encryption key ek, smart meter data m ∈ M, and timestamp t does the following:
# 1. Compute mbin = (m1, m2, ... , mb) which is a binary form of m.
# 2. Compute cti $ ←− AHE.Enc(ek,mi; ri) for each mi ∈ (m1, m2, ... , mb).
# 3. Set ct = (ct1, ct2, ... , ctb) where ct is a list of encryptions of the binary representation of energy consumption m.
# 4. Compute σ $ ←− Sig.Sign(sk, (t, ct)).
# 5. Return (pk, (t, ct, σ)).

user_info = {}

def report(id, sk, ek, m, t):
    # user
    pk = user_info[id]
    pp = pk[1]

    # convert message to binary in a list of bits
    mbin = [int(x) for x in bin(m)[2:]]
    
    # encrypt
    ct = [ahe.enc(ek[1], ek[0], m) for m in mbin]

    # sign (pk = (pk, pp, proof))
    signing_σ = sig.schnorr_sign(pp, sk, str((t, ct)))

    # get pk
    return (pk, (t, ct, signing_σ))