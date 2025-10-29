from petlib.ec import Bn
import hashlib

# key_gen generates a private/public key pair (sk, pk)
def key_gen(sec_params):
    _, g, order = sec_params
    priv_sk = order.random()
    pub_pk = priv_sk * g
    # print("sig priv:" + str(priv_sk))
    # print("sig pub:" + str(pub_pk))
    return (priv_sk, pub_pk)

# Hash hashes the commitment R and message msg to a challenge
def Hash(R, msg, order):
    h = hashlib.sha256()
    h.update(R.export())
    h.update(msg.encode())
    digest_bytes = h.digest()
    digest_bn = Bn.from_binary(digest_bytes)
    return digest_bn % order

# schnorr_sign creates a Schnorr signature on message msg using private key sk
def schnorr_sign(sec_params, sk, msg):
    _, g, order = sec_params
    k = order.random()            # nonce
    R = k * g                     # ephemeral public key
    e = Hash(R, msg, order)       # challenge
    s = (k + sk * e) % order      # signature
    return (R, s)

# schnorr_verify verifies a Schnorr signature signature on message msg using public key pk
def schnorr_verify(sec_params, pk, msg, signature):
    _, g, order = sec_params
    R, s = signature
    e = Hash(R, msg, order)                # Recompute challenge
    expected_point = s * g                  # Elliptic curve point left side
    reconstructed_point = R + e * pk        # Elliptic curve point right side
    return expected_point == reconstructed_point

