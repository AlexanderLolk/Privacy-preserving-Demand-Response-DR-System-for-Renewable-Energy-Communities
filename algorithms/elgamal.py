from Crypto.Util import number
import random
from math import gcd
from math import pow

def Alice():
    largePrime_p = number.getPrime(random.randint(1, 5))
    generatorOfGroup_g =  1
    secretKey_a = random.randint(1, (largePrime_p-1))
    A = pow(generatorOfGroup_g, secretKey_a) % largePrime_p
    pk = (largePrime_p, generatorOfGroup_g, A)

    ciphertext = Bob(pk)

    x = pow(ciphertext[1], secretKey_a) % largePrime_p
    
    message = pow(ciphertext[0], (largePrime_p - secretKey_a - 1)) * ciphertext[1] % largePrime_p

    print(f"Message is : {message}")



def Bob(pk):
    ephemeralKey_k = random.randint(1, (pk[0]-1))
    
    message_m = 6281
    
    c1 = pow(pk[1], ephemeralKey_k) % pk[0]
    c2 = message_m * pow(pk[2], ephemeralKey_k) % pk[0]

    print(f"c1 is : {c1}")
    print(f"c2 is : {c2}")

    return (c1, c2)


Alice()