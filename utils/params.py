# Parameters generation for ElGamal
# perhaps use PyCryptodome (updated library) 
from Crypto.Util import number
from .g_generator import get_generator
import random

# Elgamal
def prime_p(bits=20): 
    return number.getPrime(bits)

def generator_g(p):
    return get_generator(p)

def private_key(p):
    return generator_g(p)

# TODO change this name to be more descriptive
def computation_A(privateKey_a, largePrime_p, generatorOfGroup_g):
    return pow(generatorOfGroup_g, privateKey_a, largePrime_p)

def public_key(largePrime_p, generatorOfGroup_g, computation_A):
    return (largePrime_p, generatorOfGroup_g, computation_A)




# Schnorr's signature params
def subgroup_order_q():
    return (prime_p() - 1) // 2

