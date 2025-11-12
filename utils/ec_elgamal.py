from petlib.bn import Bn
from petlib.ec import EcPt

def key_gen(params):
    """Generates a fresh key pair"""
    _, g, o = params
    priv = o.random()
    pub = priv * g
    return (pub, priv)

# standard elgamal encryption
# def enc(pub, params, counter):
#     G, g, o = params
#     # k = r
#     k = o.random()
#     #   r * g 
#     a = k * g
#     #   r * ek  +    m    * g
#     b = k * pub + counter * g
#     return (a, b)

# def elgamal_encrypt(sec_params, ek, m_point):
#     """Encrypt a message point m_point under public key ek."""
#     _, g, order = sec_params
#     # c1 = order * g 
#     C1 = g.pt_mul(order)

#     # C2 = m_point + order * w
#     # C2 = m_point + ek.pt_mul(order)
#     C2 = m_point.pt_add(ek.pt_mul(order))
#     return (C1, C2)

def enc(pub, params, counter):
    G, g, o = params
    # k = r
    k = o.random()
    #   r * g  
    # a = k.pt_mul(g) 
    a = g.pt_mul(k)

    # if not isinstance(counter, Bn) and not isinstance(counter, EcPt):
    #     counter = Bn(counter)
    if isinstance(counter, EcPt):
        m_point = counter
    elif isinstance(counter, Bn):
        m_point = g.pt_mul(counter)
    else:
        m_point = g.pt_mul(Bn(counter))
    
    #   ek * r  +    g   *  m
    # b = pub.pt_mul(k).pt_add(g.pt_mul(counter))
    b = pub.pt_mul(k).pt_add(m_point)
    # b =  counter + pub.pt_mul(k) 
    return (a, b)

# elgamal encryption with skalar element for zero-knowledge proof
def enc_side(params, pub, counter):
    G, g, o = params
    k = o.random()
    a = k * g
    b = k * pub + counter * g
    return (a, b, k)

def add(c1, c2):
    """Add two encrypted counters"""
    a1, b1 = c1
    a2, b2 = c2
    return (a1 + a2, b1 + b2)

def mul(c1, val):
    """Multiplies an encrypted counter by a public value"""
    a1, b1 = c1
    return (val*a1, val*b1)

def randomize(params, pub, c1):
    """Rerandomize an encrypted counter"""
    zero = enc(params, pub, 0)
    return add(c1, zero)

def make_table(params):
    """Make a decryption table"""
    _, g, o = params
    table = {}
    for i in range(-1000, 1000):
        table[i * g] = i
    return table

def dec(priv, params, table, c1):
    """Decrypt an encrypted counter"""
    _, g, o = params
    a, b = c1
    # plain = b + (-priv * a)
    plain = b.pt_add(a.pt_mul(-priv))
    return plain

def dec_int(priv, params, table, c1):
    """Decrypt and convert to integer using the provided table. Returns None if out of table range."""
    plain = dec(priv, params, table, c1)
    return table.get(plain, None)

def dec_dec(priv, params, table, c1):
    C1, C2 = c1
    shared_secret = C1.pt_mul(priv)
    M = C2.pt_add(shared_secret.pt_neg())
    return M

# For Eval() in aggregator
def sub(c1, c2):
    """Subtract two encrypted counters: c1 - c2"""
    a1, b1 = c1
    a2, b2 = c2
    return (a1 + (-a2), b1 + (-b2))
    
def demo(params, ek, dk):
    # msg = Bn.from_binary(dk)
    msg = Bn(3000)
    print("Original message: ", str(msg))
    enc_msg = enc(ek, params, msg)
    # print("Encrypted message: ", str(enc_msg))
    table = make_table(params)
    dec_msg = dec_dec(dk, params, table, enc_msg)
    print("Decrypted message: ", str(dec_msg))
    
    
def elgamal_encrypt(
    plaintext: curve.Point,
    public_key: curve.Point,
    rand_func: typing.Callable[[int], bytes] | None = None,
) -> tuple[curve.Point, curve.Point]:
    rand_func = rand_func or os.urandom
    curve_ = public_key.curve

    G = curve_.G  # Base point G
    M = plaintext
    k = utils.random_int_exclusive(curve_.n, rand_func)

    C1 = k * G
    C2 = M + k * public_key
    return C1, C2


def elgamal_decrypt(
    private_key: int,
    C1: curve.Point,
    C2: curve.Point,
) -> curve.Point:
    M = C2 + (C1.curve.n - private_key) * C1
    return M