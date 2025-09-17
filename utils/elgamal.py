# Parameters generation for ElGamal
# perhaps use PyCryptodome (updated library) 
from .params import prime_p, generator_g, private_key, computation_A, public_key

def elgamal_setup():
    largePrime_p = prime_p()
    generatorOfGroup_g = generator_g()
    secretKey_a = private_key()
    A_value = computation_A(secretKey_a, largePrime_p, generatorOfGroup_g)
    pk = public_key(largePrime_p, generatorOfGroup_g, A_value)
    return pk, secretKey_a

# print(elgamal_setup())