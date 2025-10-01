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

# TODO to be reworked
def mix_id(pk_list):

    # shuffle
    pk_shuffled = pk_list.copy()
    random.shuffle(pk_shuffled)
    
    # randomize
    pk_mixed = []
    r_map = {}  # id -> ωmix (so the agg can decrypt later)

    # each shuffled pk is randomized by adding a skalar ωmix is generated for each pki
    for id_val, (pk, pp, proof) in pk_shuffled:
        _, g, order = pp
        ωmix = order.random() 
        pk_mark = pk + ωmix * g # randomize by adding ωmix * g so pk′ = pk + ωmix·g
        pk_mixed.append((id_val, (pk_mark, pp, proof)))
        r_map[id_val] = ωmix
        
    πmix = nizkp.schnorr_NIZKP_proof(pp, pk_mark, ωmix) # not the correct kind of proof?

    return (pk_mixed, r_map, πmix)

# print("mix", mix_id([("id1", skey_gen("id1")[0][1]), ("id2", skey_gen("id2")[0][1]) ]))

# mix ([('id1', (EcPt(033ad5c54716f631412d1edee9e3d24d733d24c4cafb6c948a8fd210b9),
# (EcGroup(713), EcPt(02b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21),
# 26959946667150639794667015087019625940457807714424391721682722368061),
# (16487592668787700327411264756475871888147889605471678419735314536109,
# 15677843351911813246479566031283882558293444917739170338356983039811,
# EcPt(0239a23a3a718e553dac06980183c72e2d806a2b403c000dfca50985b0)))),
# ('id2', (EcPt(02bdc8c3af46f4fc766ee996d3dae3b645257f255bd3b4e558af04f373),
# (EcGroup(713), EcPt(02b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21),
# 26959946667150639794667015087019625940457807714424391721682722368061),
# (14275928813026181319373889587855852115018972873843934298902265471464,
# 6081532365769620532019736159259168037079384161615141394057917199796,
# EcPt(03d6f5c5e2ecd533ee2768cd99c22c26020d3cbd224edb20018b2b05e8))))],
# {'id1': 18931678444940182860025687809087546505377619989474182416854594156446,
# 'id2': 19184775423589560902869614866061456474272209509369751989357596653140},
# (3800893349750884971216537661225274199943156039382845467434248082837,
# 14153630748931177267687421563799780440769580861363180919287019841092,
# EcPt(0248147293828e6ad8773cfc3a2725ac3c6f72e3ed7f7721ae3baced21)))

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
