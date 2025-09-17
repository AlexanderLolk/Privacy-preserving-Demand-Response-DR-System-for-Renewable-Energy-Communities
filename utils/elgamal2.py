# ElGamal algorithm implementation

from .params import prime_p, generator_g, secret_key, computation_A, public_key

import os
print("Running:", os.path.abspath(__file__))

def elgamal_setup():
    largePrime_p = prime_p()
    generatorOfGroup_g = generator_g()
    secretKey_a = secret_key()
    A_value = computation_A(secretKey_a, largePrime_p, generatorOfGroup_g)
    pk = public_key(largePrime_p, generatorOfGroup_g, A_value)
    return pk, secretKey_a

print(elgamal_setup())