# The algorithm Anonym({(pk_i, t, ct_i, σ_i)}i ∈ M , {r′i}_i ∈ M , skT ) allows to the blue aggregator to
# computes (ct_i, t, π_i) corresponding to the pseudo-identity pk′
# This is where the anonym function was supposed to be implemented, with its proof and verifications.
from utils.signature import Hash, schnorr_sign

def _export_bytes(x):
    if hasattr(x, "export"):
        return x.export()
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    return str(x).encode()

def Anonym(inputs=None, r_prime_list=None, secret_key_T=None):
    # TODO: ASK ABOUT SK
    # [(pk, (t, ct, sig))] = inputs
    # r_primes = [r´]
    
    print("[NOT IMP] in anonym.Anonym: compute zero-knowledge proof of knowledge signature σ_i on (pk_i, t, ct_i) and zero-knowledge proof of knowledge ")
    # 1 step  
    published = []
    for (sm_report, r_prime) in zip(inputs, r_prime_list):

        try:
            pk_tuple, body = sm_report
            pk_pt, pp, s_proof = pk_tuple
            t, cts, signature = body
        except ValueError:
            raise ValueError("Invalid input format for sm_report")
        
        pk_prime = pk_pt.pt_mul(r_prime)
        pi = "NIZKP here"
        published.append((pk_prime, cts, t, pi))

    msg_bytes = b""

    for (pk_prime, ct, t, pi) in published:
        c1, c2 = ct[0]
        msg_bytes += _export_bytes(pk_prime)
        msg_bytes += _export_bytes(c1)
        msg_bytes += _export_bytes(c2)
        # if isinstance(cts, (list, tuple)):
        #     for ct in cts:
        #         msg_bytes += _export_bytes(ct)
        # else:
        #     msg_bytes += _export_bytes(cts)
        msg_bytes += _export_bytes(t)
        msg_bytes += _export_bytes(pi)

    _, _, order = pp
    commiment = published[0][0] # pk_prime (deterministic)
    ht_bn = Hash(commiment, msg_bytes, order)

    sign_it = schnorr_sign(secret_key_T, pp, ht_bn)
    
    bb = (ht_bn, sign_it)
    pbb = published
    
    return bb, pbb

    


    
    # pass

    # publishes (ct_i, t, πi) 