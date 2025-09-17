# Parameters generation for ElGamal
# perhaps use PyCryptodome (updated library) 
from Crypto.Util import number
from .g_generator import get_highest_generator
import random

# Elgamal
def prime_p(bits=2048):
    return number.getPrime(bits)

def generator_g():
    return 0 # get_highest_generator(prime_p()) # TODO improve get_highest_generator, potentially slow

def secret_key():
    return random.randint(2, (prime_p()-1))

# TODO change this name to be more descriptive
def computation_A(secretKey_a, largePrime_p, generatorOfGroup_g):
    return pow(generatorOfGroup_g, secretKey_a, largePrime_p)

def public_key(largePrime_p, generatorOfGroup_g, A):
    return (largePrime_p, generatorOfGroup_g, A)


# Schnorr's signature params
def subgroup_order_q():
    return (prime_p() - 1) // 2

