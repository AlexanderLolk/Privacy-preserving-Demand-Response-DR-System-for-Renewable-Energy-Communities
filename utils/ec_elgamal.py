def key_gen(params):
    """Generates a fresh key pair"""
    _, g, o = params
    priv = o.random()
    pub = priv * g
    return (pub, priv)

# standard elgamal encryption
def enc(pub, params, counter):
    G, g, o = params
    # k = r
    k = o.random()
    #   r * g 
    a = k * g
    #   r * ek  +    m    * g
    b = k * pub + counter * g
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
    plain = b + (-priv * a)
    return table[plain]

# test for Eval() in aggregator
def sub(c1, c2):
    """Subtract two encrypted counters: c1 - c2"""
    a1, b1 = c1
    a2, b2 = c2
    return (a1 + (-a2), b1 + (-b2))