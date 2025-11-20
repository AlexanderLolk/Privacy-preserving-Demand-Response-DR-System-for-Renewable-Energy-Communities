from petlib.ec import Bn
import hashlib

# schnorr_challenge hashes the elements for the challenge used in Schnorrs proof
def schnorr_NIZKP_challenge(elements):
    """

    :param elements: 

    """
    elem = [len(elements)] + elements
    elem_str = map(str, elem) 
    elem_len = map(lambda x: "%s||%s" % (len(x) , x), elem_str) 
    state = "|".join(elem_len)
    Hash = hashlib.sha256()
    Hash.update(state.encode("utf8"))
    return Hash.digest()

# schnorr_proof creates the NIZKP of knowledge of the secret key (rewrite the explanation)
def schnorr_NIZKP_proof(pk, sec_params, sk, msg=""):
    """

    :param pk: 
    :param sec_params: 
    :param sk: 
    :param msg:  (Default value = "")

    """
    _, g, order = sec_params
    r = order.random()            # nonce
    commitment = r * g            # 
    
    # challenge
    challenge_hash = schnorr_NIZKP_challenge([
        g.export().hex(),
        pk.export().hex(),
        commitment.export().hex(),
        msg
    ])
    challenge = Bn.from_binary(challenge_hash) % order # from_binary Creates a Big Number from a byte sequence representing the number in Big-endian 8 byte atoms.
    response = (r - challenge * sk) % order 
    return (challenge, response, commitment)

# schnorr_NIZKP_verify verifies the NIZKP of knowledge of the secret key
def schnorr_NIZKP_verify(pk, sec_params, proof, msg=""):
    """

    :param pk: 
    :param sec_params: 
    :param proof: 
    :param msg:  (Default value = "")

    """
    _, g, order = sec_params
    c, s, W = proof
    # reconstruct commitment
    W_check = (s * g + c * pk)
    
    # recompute challenge
    challenge = schnorr_NIZKP_challenge([
        g.export().hex(),   
        pk.export().hex(),
        W_check.export().hex(),
        msg
    ])
    check = Bn.from_binary(challenge) % order
    return c == check and W == W_check