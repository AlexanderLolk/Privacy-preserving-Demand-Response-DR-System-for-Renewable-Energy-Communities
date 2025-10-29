from petlib.ec import EcGroup, Bn
import random
import utils.signature as sig
import utils.NIZKP as nizkp
import utils.ec_elgamal as ahe
import utils.shuffle as shuffle
from utils.dec_proof import elgamal_encrypt, prove_correct_decryption

def pub_param(nid=713):
    group_G = EcGroup(nid)
    # g is the base point of the curve, which is also called the generator
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

    m_scalar = Bn(42)   # just a sample message for proof
    M = m_scalar * pp[1]

    (C1, C2) = elgamal_encrypt(pp, ek, M)

    # Generate proof of correct decryption
    πdk = prove_correct_decryption(pp, ek, C1, C2, M, dk)
    return ((ek, pp, πdk), dk)


# mix shuffles a n anonymized list of pk_i
def mix_id(ID_pk):
    # ID_pk: list of tuples (id, (pk, pp, proof))
    
    if not ID_pk:
        return ([], {}, None)
    
    N = len(ID_pk)
    Id_A_pk = []
    for idpk in ID_pk:
        # id = idpk[0] 
        pk = idpk[1][0]
        # Id_A_pk.append((id, pk))
        Id_A_pk.append(pk)

    e_prime, r_prime, ψ = shuffle.GenShuffle(Id_A_pk)
    # proof of shuffle and anonymised list of pks
    πmix_proof= shuffle.GenProof(Id_A_pk, e_prime, r_prime, ψ, pk="need to remove")

    return (e_prime, r_prime, πmix_proof)

# Report(id, sk, ek, m, t) → (pk, (t, ct, σ))
user_info = {}

def report(id, sk, ek, m, t, user_info):
    # to get pk sended back
    pk = user_info[id]
    pp = pk[1]

    # convert message to binary in a list of bits
    mbin = [int(x) for x in bin(m)[2:]]
    
    # encrypt
    ct = [ahe.enc(ek[1], ek[0], m) for m in mbin]

    # sign (pk = (pk, pp, proof))
    signing_σ = sig.schnorr_sign(pp, sk, str((t, ct)))

    return (pk, (t, ct, signing_σ))

# ((EcPt(0354659d38ca5ac09a85787ae2d4b5ce59375213599042680aac37ecb1), (EcGroup(713), EcPt(02b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21), 26959946667150639794667015087019625940457807714424391721682722368061), (1624255765264479900433662888001760247682109420038501048082348925063, 17289068970920576793031962993214834139792054926565669136630683249189, EcPt(036055e1be9e5173107d2765473dff24025ddf983172bfa2b5f6c8b9a8))), (1761737702, [(EcPt(0349862b122c313aade5fcc7c498987a6189909acf32b5f5c47e489b48), EcPt(02111124a1e6e513d178a4b03a0c48e867fc285f847fd624150af7e5c7)), (EcPt(035c3af87177cd526d5aeb9399934e1cccf0df5fc216212a9dadeadbc1), EcPt(03c37d43dbfabba5aff72789c0b9356ec555d0288c84a9a7a9d3563e1c)), (EcPt(026d0fb2690217b6003352131f9c0a96b0a8e7c956409cdd9007de5a1d), EcPt(03631cc107267bfef460556aab4c968090a7ad12976c63f742dcf8ff15)), (EcPt(035714e15ca92a05363549142ea8b1f812683ba58b9528e2781c2e1e32), EcPt(03da6787b8ef4ca9cb3fff36c9bc6fd058ea0ec9a1ac0df376eb9f6910))], (EcPt(03c732c752e4802634cc6faa7c38e72fdfbf31bea1943a058b1b4ad032), 1733081658665812511647271052627054037715719227605926705789863678318)))
# ((EcPt(02fb539108d085d94459b28897ea74ad251de48fa4e33c7b013f4751e1), (EcGroup(713), EcPt(02b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21), 26959946667150639794667015087019625940457807714424391721682722368061), (17674676353647088108568714657971968053227815126063992831138252291258, 13888839188553144653225579085259305002016201691182827381782550792471, EcPt(0371a6efff0d417c0c9c766ad37c6fe8a853e103efffa2b67d92ad2b6e))), (1761737702, [(EcPt(020ab53919ec5f60096d235f4b8c775bafaa31c93a6bfabbd1f1b5ceaa), EcPt(037b579a5d265fceb1bce664d6e49a2175caf5867506f661402801bae1)), (EcPt(025f8290150a6bdcf221077eb5ab40ef03219234551041fc66232a813f), EcPt(02252a3f3a557d420d55865b6184dae8864a0cacbb3b9b4f4ef996a242)), (EcPt(02725cd14b9dab9ff9fb3a748b0bfe2b1be0da308c7e80eb917eb39444), EcPt(03173471e2ebcce3fc99a3510ec495b8c3e4ecfd64f1dc08b3adc5a5ba)), (EcPt(03426698916e27893e1cb79a74df111573bfc77ae40d654f2aadaa6401), EcPt(03a3d4e16d5b81ea4e34b77ae7d0386d58696b3d9cdefbb42ad71188fc))], (EcPt(03ac08cacac19a84ebef966fd4a7a6e4a429811b4cc971f2d0c88f1d9d), 19209968981633345582058063132272612263965665499905258406739787813966)))
# ((EcPt(03285513e5c11e453418370cfba2705088323a1e46eab6c64acecbc13a), (EcGroup(713), EcPt(02b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21), 26959946667150639794667015087019625940457807714424391721682722368061), (8032394310149703887954656818411247543495006630408874454279777033674, 21876797716274202444358354339271551163801634646988774713689976356174, EcPt(02e75a1abb42b3b9557f0b8b396146b39bbb829013bcbf8c5c137deaff))), (1761737702, [(EcPt(039d44a5291f964851c28b5fdcba7dfdfeeae1608bc98c10d64c25fb70), EcPt(023416ed24fed57feac3ea861796d67df3caf54498c892b4c0655c90e2))], (EcPt(02ad96e6c3cc7bcc2ead0bb4e42c7d58fa857957508f13450fe2d6ea74), 6513654824252141079615656138957924934374318259736354347844673348317)))