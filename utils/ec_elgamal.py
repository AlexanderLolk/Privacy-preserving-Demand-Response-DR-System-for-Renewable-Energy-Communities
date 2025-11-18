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
    return table[plain]
    
def demo(params, ek, dk):
    # msg = Bn.from_binary(dk)
    msg = Bn(5)
    print("Original message: ", str(msg))
    enc_msg = enc(ek, params, msg)
    # print("Encrypted message: ", str(enc_msg))
    table = make_table(params)
    dec_msg = dec(dk, params, table, enc_msg)
    print("Decrypted message: ", str(dec_msg))
    
