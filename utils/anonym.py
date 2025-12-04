# The algorithm Anonym({(pk_i, t, ct_i, σ_i)}i ∈ M , {r′i}_i ∈ M , skT ) allows to the blue aggregator to
# computes (ct_i, t, π_i) corresponding to the pseudo-identity pk′
# This is where the anonym function was supposed to be implemented, with its proof and verifications.
from utils.signature import Hash, schnorr_sign

def _export_bytes(x):
    """

    Args:
      x: 

    Returns:
        bytes: 

    """
    if hasattr(x, "export"):
        return x.export()
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    return str(x).encode()

def Anonym(inputs=None, r_prime_list=None, secret_key_T=None):
    """

    Args:
      inputs: (list[tuple[tuple[EcPt, tuple[EcGroup, EcPt, Bn], tuple[Bn, Bn, EcPt]], tuple[int, list[tuple[EcPt, EcPt]], tuple[Bn, Bn, EcPt]]]]) Default value = None)
      r_prime_list: (list[EcPt]) Default value = None)
      secret_key_T: (Bn) Default value = None)

    Returns:
        tuple[tuple[Bn, tuple[Bn, Bn, EcPt]], tuple[EcPt, tuple[EcPt, EcPt], int, str(placeholder)]]
    """
    
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
        
        # TODO check if index is correct, normally it is done by ZKP
        pk_prime = (r_prime) * pk_pt 
        pi = "NIZKP here"
        published.append((pk_prime, cts, t, pi))

    msg_bytes = b""

    for (pk_prime, ct, t, pi) in published:
        c1, c2 = ct[0]
        msg_bytes += _export_bytes(pk_prime)
        msg_bytes += _export_bytes(c1)
        msg_bytes += _export_bytes(c2)
        msg_bytes += _export_bytes(t)
        msg_bytes += _export_bytes(pi)

    
    commiment = published[0][0] # pk_prime (usage is to make sure it's deterministic)
    # Report: hash it (step 8 sequence chart)
    ht_bn = Hash(commiment, msg_bytes, pp[2])

    sign_it = schnorr_sign(secret_key_T, pp, ht_bn)
    
    bb = (ht_bn, sign_it)
    pbb = published
    
    return bb, pbb