import hashlib
import threshold_crypto as tc

# code inspired by https://mit6875.github.io/PAPERS/Schnorr-POK-DLOG.pdf page 5 (The authentication protocol)

def schnorr_NIZKP_challenge(elements):
    """Create a deterministic SHA-256 challenge from the provided elements.

    The function stringifies and length-prefixes each element, joins them
    with a separator and returns the raw SHA-256 digest. Callers usually
    convert the digest into an int and reduce modulo the group order.

    Args:
        elements (list): Sequence of values which will be stringified and
                         included in the challenge hash (strings or bytes).

    Returns:
        bytes: Raw SHA-256 digest to be interpreted by the caller.
    """
    elem = [len(elements)] + elements
    elem_str = map(str, elem)
    elem_len = map(lambda x: "%s||%s" % (len(x), x), elem_str)
    state = "|".join(elem_len)
    Hash = hashlib.sha256()
    Hash.update(state.encode("utf8"))
    return Hash.digest()

def schnorr_NIZKP_proof(pk, pp, sk, msg=""):
    """Create a Schnorr non-interactive proof of knowledge of `sk`.

    The proof demonstrates knowledge of the secret scalar `sk` such that
    `pk = sk * g` without revealing `sk`. It returns the tuple
    (challenge, response, commitment) where the challenge is derived via
    `schnorr_NIZKP_challenge` (Fiat–Shamir).

    Args:
        pk (ECC Point): Public key point corresponding to `sk`.
        sec_params (tc.CurveParameters): Curve parameters.
        sk (int): Secret scalar (private key).
        msg (str): Optional context string included in the challenge.

    Returns:
        tuple: (challenge (int), response (int), commitment (ECC Point)).
    """
    g = pp[1]
    order = pp[2]
    
    r = tc.number.random_in_range(1, order)  # nonce
    commitment = int(r) * g

    # Create challenge using point coordinates
    challenge_hash = schnorr_NIZKP_challenge([
        str(g.x), str(g.y),
        str(pk.x), str(pk.y),
        str(commitment.x), str(commitment.y),
        msg
    ])
    challenge = int.from_bytes(challenge_hash, "big") % int(order)
    response = (int(r) - int(challenge) * int(sk)) % int(order)
    return (challenge, response, commitment)

def schnorr_NIZKP_verify(pk, pp, proof, msg=""):
    """Verify a Schnorr NIZKP produced by `schnorr_NIZKP_proof`.

    The verifier reconstructs the commitment from the provided response
    and challenge, recomputes the Fiat–Shamir challenge and checks
    consistency.

    Args:
        pk (ECC Point): Public key point.
        sec_params (tc.CurveParameters): Curve parameters.
        proof (tuple): (challenge (int), response (int), commitment (ECC Point)).
        msg (str): Optional context string that must match the one used by
                   the prover.

    Returns:
        bool: True if the proof is valid, False otherwise.
    """
    g = pp[1]
    order = pp[2]
    c, s, W = proof
    
    # Reconstruct commitment: W_check = s * g + c * pk
    W_check = (int(s) * g) + (int(c) * pk)
    
    # Recompute challenge using reconstructed commitment
    challenge_hash = schnorr_NIZKP_challenge([
        str(g.x), str(g.y),
        str(pk.x), str(pk.y),
        str(W_check.x), str(W_check.y),
        msg
    ])
    check = int.from_bytes(challenge_hash, "big") % order
    
    return int(c) == check and W == W_check