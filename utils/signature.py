from petlib.ec import Bn
import hashlib

# key_gen generates a private/public key pair (sk, pk)
def key_gen(sec_params):
    """

    :param sec_params: 

    """
    _, g, order = sec_params
    priv_sk = order.random()
    pub_pk = priv_sk * g
    # print("sig priv:" + str(priv_sk))
    # print("sig pub:" + str(pub_pk))
    return (priv_sk, pub_pk)

# Hash hashes the commitment R and message msg to a challenge
def Hash(R, msg, order):
    """

    :param R: 
    :param msg: 
    :param order: 

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
    """

    :param sk: 
    :param sec_params: 
    :param msg: 

    """
    _, g, order = sec_params
    k = order.random()            # nonce
    ephemeral_key = k * g                     # ephemeral public key
    challenge_hash = Hash(ephemeral_key, msg, order)       # challenge
    signature = (k + sk * challenge_hash) % order      # signature
    return (ephemeral_key, signature) 

# schnorr_verify verifies a Schnorr signature signature on message msg using public key pk
def schnorr_verify(pk, sec_params, msg, signature):
    """

    :param pk: 
    :param sec_params: 
    :param msg: 
    :param signature: 

    """
    _, g, order = sec_params
    R, s = signature
    e = Hash(R, msg, order)                 # Recompute challenge
    expected_point = s * g                  # Elliptic curve point left side
    reconstructed_point = R + e * pk        # Elliptic curve point right side
    return expected_point == reconstructed_point

# signs lists of messages
def schnorr_sign_list(sk, sec_params, msg_list):
    """

    :param sk: 
    :param sec_params: 
    :param msg_list: 

    """
    signatures = []
    for msg in msg_list:
        sign = schnorr_sign(sk, sec_params, msg)
        signatures.append(sign)
    return signatures
    
# 
def schnorr_verify_list(pk, sec_params, msg_list, signatures):
    """

    :param pk: 
    :param sec_params: 
    :param msg_list: 
    :param signatures: 

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