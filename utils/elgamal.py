# Parameters generation for ElGamal
# perhaps use PyCryptodome (updated library) 
from .params import prime_p, generator_g, private_key, computation_A, public_key

largePrime_p = prime_p()
generatorOfGroup_g = generator_g(largePrime_p)

def elgamal_setup():
    secretKey_a = private_key(largePrime_p)
    # public_key h = g^a mod p
    public_key = pow(generatorOfGroup_g, secretKey_a, largePrime_p)
    return public_key, secretKey_a

def el_encrypt_additive(pk, message_m):    
    ephemeralKey_k = generator_g(largePrime_p) # randomized
    # c1 = g^k mod p
    c1 = pow(generatorOfGroup_g, ephemeralKey_k, largePrime_p)
    # c2 = message_m * pow(pk, ephemeralKey_k) not additive, 
    # c2 = (g^m * pk^k) mod p
    c2 = (pow(generatorOfGroup_g, message_m, largePrime_p) * pow(pk, ephemeralKey_k, largePrime_p)) % largePrime_p
    return (c1, c2)

def el_decrypt_additive(secretKey_a, ciphertext):
    c1, c2 = ciphertext

    # c1^(p-1-a) mod p
    computed_c1 = pow(c1, (largePrime_p - secretKey_a - 1), largePrime_p)
    
    # gm = c2 * (c1^a)^-1 mod p
    g_m = (computed_c1 * c2) % largePrime_p 
    
    # solve the Discrete Logarithm Problem to find m
    m = -1 # Default value if not found
    for potential_m in range(largePrime_p):
        if pow(generatorOfGroup_g, potential_m, largePrime_p) == g_m:
            m = potential_m
            break

    return m
    # c1Star = pow(ciphertext[0], (pk[0] - secretKey_a - 1), pk[0])
    # message = c1Star * ciphertext[1] % pk[0]

pu, se = elgamal_setup()
cipher = el_encrypt_additive(pu, 10)
print(el_decrypt_additive(se, cipher))