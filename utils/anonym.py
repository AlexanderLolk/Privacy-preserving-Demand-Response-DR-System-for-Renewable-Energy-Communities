from utils.signature import Hash, schnorr_sign

def __export_bytes(x):
    """
    Helper function to serialize various object types into bytes for hashing.
    
    Args:
        x: The object to serialize (EcPoint, bytes, bytearray, or other types).

    Returns:
        bytes: The byte representation of the object.
    """
    if hasattr(x, "export"):
        return x.export()
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    return str(x).encode()

def Anonym(inputs=None, r_prime_list=None, secret_key_T=None):
    """
    Aggregates user reports, derives anonymized public keys, and signs the batch for the bulletin board.

    Current Limitations:
    - It uses a placeholder string instead of a NIZKP instead of generating real Zero-Knowledge Proofs 
      linking the new `pk_prime` to the original `pk` and signature.
    - It assumes alignment between `inputs` and `r_prime_list`.
    - A CGate has not been implemented


    Args:
        inputs (list): List of smart meter reports. Each report is a tuple:
                       ( (pk, pp, proof), (t, cts, signature) )
        r_prime_list (list): List of blinding factors (points or scalars) used to re-randomize the public keys.
        secret_key_T (int): The private signing key of the entity (TTP/Aggregator) validating this batch.

    Returns:
        tuple: (Batch_Signature, Published_List)
               - Batch_Signature: (Hash_Integer, Schnorr_Signature)
               - Published_List: List of (pk_prime, cts, t, pi) tuples.
    """
    
    print("[NOT IMP] in anonym.Anonym: compute zero-knowledge proof of knowledge signature σ_i on (pk_i, t, ct_i) and zero-knowledge proof of knowledge ")
 
    published = []
    for (sm_report, r_prime) in zip(inputs, r_prime_list):
        try:
            pk_tuple, body = sm_report
            pk, pp, s_proof = pk_tuple
            t, cts, signature = body
        except ValueError:
            raise ValueError("Invalid input format for sm_report")
        
        # TODO check if index is correct, normally it is done by ZKP
        # ANSWER: THEY DO NOT ALIGN!!!!!!
        # FOR NOW, AGG HAS A MAP TO STORE THE pk TO pk_prime
        # pk_prime = (r_prime) * pk_pt
        pk_prime = r_prime + pk

        # placeholder proof
        pi = "NIZKP here"
        published.append((pk_prime, cts, t, pi))

    msg_bytes = b""

    for (pk_prime, ct, t, pi) in published:
        # TODO maybe just str() the list of cts
        c1, c2 = ct[0]
        msg_bytes += __export_bytes(pk_prime)
        msg_bytes += __export_bytes(c1)
        msg_bytes += __export_bytes(c2)
        msg_bytes += __export_bytes(t)
        msg_bytes += __export_bytes(pi)
    
    # Use the first pk_prime as the 'randomness commitment' (R) for the Hash function
    # This binds the hash to the specific curve/batch context.
    commiment = published[0][0] # pk_prime (usage is to make sure it's deterministic)
    
    # hash it
    ht_bn = Hash(commiment, msg_bytes, pp[2])

    # Sign the batch hash with the authority's secret key
    sign_it = schnorr_sign(secret_key_T, pp, ht_bn)
    
    bb = (ht_bn, sign_it)
    pbb = published
    
    return bb, pbb