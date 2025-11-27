import threshold_crypto as tc
from Crypto.PublicKey import ECC

# params for threshold_crypto
# G                 = ECC._curves[curve_name]
# g                 = curve_params.P 
# order             = curve_params.order
# order.random()    = number.random_in_range(1, curve_params.order) AKA d
# pk                = Q
# sk                = d


def test_tp_decrypt():
    curve_params = tc.CurveParameters('P-256')
    print("curve_params: " + str(curve_params))
    print("order: " + str(type(curve_params.order)))
    
    # key = ECC.generate(curve="P-256")
    # print("key from ECC: " + str(key))
    

    thresh_params = tc.ThresholdParameters(2, 2)

    pub_key, key_shares = tc.create_public_key_and_shares_centralized(curve_params, thresh_params)

    # print("len of key_shares: " + str(len(key_shares)))
    encrypted_message = tc.encrypt_message(str(123), pub_key)

    reconstruct_shares = [key_shares[0],key_shares[1]]  # choose 3 of 5 key shares

    partial_decryptions = [tc.compute_partial_decryption(encrypted_message, share) for share in reconstruct_shares]

    decrypted_message = tc.decrypt_message(partial_decryptions, encrypted_message, thresh_params)

    print(decrypted_message)
   
# test_tp_decrypt()

def test_tp_deterministic_decrypt():
    curve_params = tc.CurveParameters('P-256')
    print("order: " + str(curve_params.order))
    print("order type: " + str(type(curve_params.order)))
    
    thresh_params = tc.ThresholdParameters(2, 2)
    pub_key, key_shares = tc.create_public_key_and_shares_centralized(curve_params, thresh_params)
    encrypted_message = tc.encrypt_message(str(0), pub_key)
    
    try_encrypted_message


# needed for ekey_gen
def key_gen(sec_params):
    thresh_params = tc.ThresholdParameters(2, 2)
    public_key, key_shares = tc.create_public_key_and_shares_centralized(sec_params, thresh_params)
    return public_key, key_shares

def enc(public_key, pp, message):
    
    if not isinstance(message, str):
        message = str(message)
        
    return tc.encrypt_message(message, public_key)  

def part_dec(encrypted_message, key_share):
    return tc.compute_partial_decryption(encrypted_message, key_share)

def dec(partial_decryptions, encrypted_message, threshold_params):
    return tc.decrypt_message(partial_decryptions, encrypted_message, threshold_params)



# from petlib.bn import Bn
# from petlib.ec import EcPt

# def key_gen(params):
#     """Generates a fresh key pair

#     :param params: 

#     """
#     _, g, o = params
#     priv = o.random()
#     pub = priv * g
#     return (pub, priv)

# # standard elgamal encryption
# # def enc(pub, params, counter):
# #     G, g, o = params
# #     # k = r
# #     k = o.random()
# #     #   r * g 
# #     a = k * g
# #     #   r * ek  +    m    * g
# #     b = k * pub + counter * g
# #     return (a, b)

# def enc(pub, params, counter):
#     """

#     :param pub: 
#     :param params: 
#     :param counter: 

#     """
#     G, g, o = params
#     # k = r
#     k = o.random()
#     #   r * g  
#     # a = k.pt_mul(g) 
#     a = g.pt_mul(k)

#     # if not isinstance(counter, Bn) and not isinstance(counter, EcPt):
#     #     counter = Bn(counter)
#     if isinstance(counter, EcPt):
#         m_point = counter
#     elif isinstance(counter, Bn):
#         m_point = g.pt_mul(counter)
#     else:
#         m_point = g.pt_mul(Bn(counter))
    
#     #   ek * r  +    g   *  m
#     # b = pub.pt_mul(k).pt_add(g.pt_mul(counter))
#     b = pub.pt_mul(k).pt_add(m_point)
#     # b =  counter + pub.pt_mul(k) 
#     return (a, b)

# def make_table(params):
#     """Make a decryption table

#     :param params: 

#     """
#     _, g, o = params
#     table = {}
#     for i in range(-1000, 1000):
#         table[i * g] = i
#     return table

# def dec(priv, params, table, c1):
#     """Decrypt an encrypted counter

#     :param priv: 
#     :param params: 
#     :param table: 
#     :param c1: 

#     """
#     _, g, o = params
#     a, b = c1
#     # plain = b + (-priv * a)
#     plain = b.pt_add(a.pt_mul(-priv))
#     return table[plain]
    

    

# def demo(params, ek, dk):
#     """

#     :param params: 
#     :param ek: 
#     :param dk: 

#     """
#     # msg = Bn.from_binary(dk)
#     msg = Bn(5)
#     print("Original message: ", str(msg))
#     enc_msg = enc(ek, params, msg)
#     # print("Encrypted message: ", str(enc_msg))
#     table = make_table(params)
#     dec_msg = dec(dk, params, table, enc_msg)
#     print("Decrypted message: ", str(dec_msg))
    
