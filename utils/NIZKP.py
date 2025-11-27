from petlib.ec import Bn
import hashlib
import threshold_crypto as tc

# schnorr_challenge hashes the elements for the challenge used in Schnorrs proof
def schnorr_NIZKP_challenge(elements):
    """Create a deterministic SHA-256 challenge from the provided elements.

    The function stringifies and length-prefixes each element, joins them
    with a separator and returns the raw SHA-256 digest. Callers usually
    convert the digest into a `Bn` and reduce modulo the group order.

    Args:
        elements (list): Sequence of values which will be stringified and
                         included in the challenge hash (strings or bytes).

    Returns:
        bytes: Raw SHA-256 digest to be interpreted by the caller.
    """
    elem = [len(elements)] + elements
    elem_str = map(str, elem)
    elem_len = map(lambda x: "%s||%s" % (len(x) , x), elem_str)
    state = "|".join(elem_len)
    Hash = hashlib.sha256()
    Hash.update(state.encode("utf8"))
    return Hash.digest()

# schnorr_proof creates the NIZKP of knowledge of the secret key (rewrite the explanation)
# def schnorr_NIZKP_proof(pk, sec_params, sk, msg=""):
#     """Create a Schnorr non-interactive proof of knowledge of `sk`.

#     The proof demonstrates knowledge of the secret scalar `sk` such that
#     `pk = sk * g` without revealing `sk`. It returns the tuple
#     (challenge, response, commitment) where the challenge is derived via
#     `schnorr_NIZKP_challenge` (Fiat–Shamir).

#     Args:
#         pk (EcPt): Public key point corresponding to `sk`.
#         sec_params (tuple): (EcGroup, generator g (EcPt), order (Bn)).
#         sk (Bn): Secret scalar (private key).
#         msg (str): Optional context string included in the challenge.

#     Returns:
#         tuple: (challenge (Bn), response (Bn), commitment (EcPt)).
#     """
#     _, g, order = sec_params
#     r = order.random()            # nonce
#     commitment = r * g

#     # challenge
#     challenge_hash = schnorr_NIZKP_challenge([
#         g.export().hex(),
#         pk.export().hex(),
#         commitment.export().hex(),
#         msg
#     ])
#     challenge = Bn.from_binary(challenge_hash) % order # from_binary Creates a Big Number from a byte sequence representing the number in Big-endian 8 byte atoms.
#     response = (r - challenge * sk) % order 
#     return (challenge, response, commitment)

def schnorr_NIZKP_proof(pk, sec_params, sk, msg=""):
    g = sec_params.P
    order = sec_params.order
    
    r = tc.number.random_in_range(1, order) #nonce
    commitment = r * g

    challenge_hash = schnorr_NIZKP_challenge([
        str(g.x), str(g.y),
        str(pk.x), str(pk.y),
        str(commitment.x), str(commitment.y),
        msg
    ])
    challenge = int.from_bytes(challenge_hash, "big") % order
    response = (r - challenge * sk) % order
    return (challenge, response, commitment)

# schnorr_NIZKP_verify verifies the NIZKP of knowledge of the secret key
def schnorr_NIZKP_verify(pk, sec_params, proof, msg=""):
    """Verify a Schnorr NIZKP produced by `schnorr_NIZKP_proof`.

    The verifier reconstructs the commitment from the provided response
    and challenge, recomputes the Fiat–Shamir challenge and checks
    consistency.

    Args:
        pk (EcPt): Public key point.
        sec_params (tuple): (EcGroup, generator g (EcPt), order (Bn)).
        proof (tuple): (challenge (Bn), response (Bn), commitment (EcPt)).
        msg (str): Optional context string that must match the one used by
                   the prover.

    Returns:
        bool: True if the proof is valid, False otherwise.
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