from petlib.ec import Bn
import hashlib
from Crypto.PublicKey import ECC
import threshold_crypto as tc
import random

# key_gen generates a private/public key pair (sk, pk)
# def key_gen(sec_params):
#     """Generate a Schnorr keypair.

#     Args:
#         sec_params (tuple): (EcGroup, generator EcPt, order Bn).

#     Returns:
#         tuple: (sk (Bn), pk (EcPt)) where pk = sk * g.
#     """
#     _, g, order = sec_params
#     priv_sk = order.random()
#     pub_pk = priv_sk * g
#     return (priv_sk, pub_pk)

def key_gen(pp):
    g = pp.P
    order = pp.order
    priv_sk = tc.number.random_in_range(1, order)
    pub_pk = priv_sk * g
    return (priv_sk, pub_pk)

# Hash hashes the commitment R and message msg to a challenge
def Hash(R, msg, order):
    """Compute the challenge hash used in Schnorr signing.

    The function hashes the ephemeral commitment `R` together with the
    message `msg` and returns a scalar reduced modulo `order`.

    Args:
        R (EcPt): ephemeral commitment point (ephemeral_key).
        msg:
        order (Bn): group order used to reduce the digest.

    Returns:
        Bn:
    """
    h = hashlib.sha256()
    h.update(R.export())

    # Report: This is to ensure we convert msg to bytes from, for instance, a signature
    if isinstance(msg, bytes):
        msg_bytes = msg
    elif isinstance(msg, Bn):
        msg_bytes = msg.binary()
    elif hasattr(msg, "export"):
        msg_bytes = msg.export()
    else:
        msg_bytes = str(msg).encode()

    h.update(msg_bytes)
    digest_bytes = h.digest()
    digest_bn = Bn.from_binary(digest_bytes)
    return digest_bn % order

# schnorr_sign creates a Schnorr signature on message msg using private key sk
def schnorr_sign(sk, sec_params, msg):
    """Create a Schnorr signature on `msg` using secret key `sk`.

    Args:
        sk (Bn): signing secret scalar.
        sec_params (tuple): (EcGroup, generator EcPt, order Bn).
        msg: message to sign (can be bytes, Bn, EcPt or convertible to str).

    Returns:
        tuple: (ephemeral_key (EcPt), signature (Bn)).
    """
    _, g, order = sec_params
    k = order.random()            # nonce
    ephemeral_key = k * g                     # ephemeral public key
    challenge_hash = Hash(ephemeral_key, msg, order)       # challenge
    signature = (k + sk * challenge_hash) % order      # signature
    return (ephemeral_key, signature) 

# schnorr_verify verifies a Schnorr signature signature on message msg using public key pk
def schnorr_verify(pk, sec_params, msg, signature):
    """Verify a Schnorr signature produced by `schnorr_sign`.

    Args:
        pk (EcPt): public signing key.
        sec_params (tuple): (EcGroup, generator EcPt, order Bn).
        msg: the signed message (must match prover's input).
        signature (tuple): (R (EcPt), s (Bn)).

    Returns:
        bool: True if signature is valid, False otherwise.
    """
    _, g, order = sec_params
    R, s = signature
    e = Hash(R, msg, order)                 # Recompute challenge
    expected_point = s * g                  # Elliptic curve point left side
    reconstructed_point = R + e * pk        # Elliptic curve point right side
    return expected_point == reconstructed_point

# signs lists of messages
def schnorr_sign_list(sk, sec_params, msg_list):
    """Sign a list of messages using `schnorr_sign`.

    Returns a list of signature tuples corresponding to each message.

    Args:
        sk (Bn): signing secret.
        sec_params (tuple): (EcGroup, generator EcPt, order Bn).
        msg_list (iterable): sequence of messages to sign.

    Returns:
        list: list of signatures [(R, s), ...].
    """
    signatures = []
    for msg in msg_list:
        sign = schnorr_sign(sk, sec_params, msg)
        signatures.append(sign)
    return signatures


def schnorr_verify_list(pk, sec_params, msg_list, signatures):
    """Verify a list of Schnorr signatures against the corresponding msgs.

    Returns a tuple (all_valid, results) where `all_valid` is True when all
    signatures verify, and `results` contains per-message outcomes.

    Args:
        pk (EcPt): public signing key.
        sec_params (tuple): (EcGroup, generator EcPt, order Bn).
        msg_list (iterable): messages to verify.
        signatures (iterable): signatures to verify.

    Returns:
        tuple: (all_valid (bool), results (list of (index, msg, bool))).
    """
    results = []
    for i, (msg, signature) in enumerate(zip(msg_list, signatures)):
        is_valid = schnorr_verify(pk, sec_params, msg, signature)
        if not is_valid:
            results.append((i, msg, False))
        else:
            results.append((i, msg, True))
    
    all_valid = all(r[2] for r in results)
    return (all_valid, results)