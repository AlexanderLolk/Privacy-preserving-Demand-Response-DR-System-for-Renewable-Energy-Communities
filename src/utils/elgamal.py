# Parameters generation for ElGamal
# perhaps use PyCryptodome (updated library) 
from .params import prime_p, generator_g, secret_key, A, public_key

def el_setup():
    largePrime_p = prime_p()
    generatorOfGroup_g = generator_g()
    secretKey_a = secret_key()
    A_value = A(secretKey_a, largePrime_p, generatorOfGroup_g)
    pk = public_key(largePrime_p, generatorOfGroup_g, A_value)
    return pk, secretKey_a

# print(el_setup())