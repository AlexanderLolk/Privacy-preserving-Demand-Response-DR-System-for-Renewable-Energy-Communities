# Parameters generation for ElGamal
# perhaps use PyCryptodome (updated library) 
from Crypto.Util import number
import random

def prime_p():
    return number.getPrime(random.randint(2000, 2024))

def generator_g():
    return 35 # add elgamlCore here. get the highest g, not how it should be made, but for testing it is okay

def secret_key():
    return random.randint(2, (prime_p()-1))

def A(secretKey_a, largePrime_p, generatorOfGroup_g):
    return pow(generatorOfGroup_g, secretKey_a, largePrime_p)

def public_key(largePrime_p, generatorOfGroup_g, A):
    return (largePrime_p, generatorOfGroup_g, A)