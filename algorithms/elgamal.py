from Crypto.Util import number
import random
from math import gcd

def Alice():
    print("ALICE SIDE\n")
    
    largePrime_p = number.getPrime(random.randint(20, 40))
    print(f"p is : {largePrime_p}")
    
    generatorOfGroup_g = 35
    
    secretKey_a = random.randint(2, (largePrime_p-1))
    print(f"alice's secretKey a is : {secretKey_a}")
    
    A = pow(generatorOfGroup_g, secretKey_a, largePrime_p)
    print(f"alice's A is : {A}")
    
    pk = (largePrime_p, generatorOfGroup_g, A)
    print(f"Alice's Public key contains : {pk}")
    
    print("SENDING PUBLIC KEY TO BOB")
    ciphertext = Bob(pk)
    print("\nALICE SIDE\n")
    
    print(f"Alice received ciphertext from Bob : {ciphertext}")
    print(f"From ciphertext, c1 is : {ciphertext[0]}")
    print(f"From ciphertext, c2 is : {ciphertext[1]}")

    # x = pow(ciphertext[1], secretKey_a) % largePrime_p
    # note: Not have the modular part in the calulation it will make it whole progress much longer, could take hours.
    c1Star = pow(ciphertext[0], (largePrime_p - secretKey_a - 1), largePrime_p)
    print(f"c1Star is : {c1Star}")
    message = c1Star * ciphertext[1] % largePrime_p

    print(f"Message is from encrypted message : {message}")



def Bob(pk):
    print("\nBob SIDE\n")
    print(f"Bob received Public key from Alice : {pk}")
    ephemeralKey_k = random.randint(1, (pk[0]-1))
    print(f"Bob's ephemeralKey k is : {ephemeralKey_k}")
    
    message_m = 6281
    print(f"Bob's message m is : {message_m}")
    
    c1 = pow(pk[1], ephemeralKey_k, pk[0])
    c2 = message_m * pow(pk[2], ephemeralKey_k, pk[0])

    print(f"c1 is : {c1}")
    print(f"c2 is : {c2}")

    return (c1, c2)

Alice()

def el_setup():
    largePrime_p = number.getPrime(random.randint(2000, 2024))
    generatorOfGroup_g = 35 # add elgamlCore here. get the highest g, not how it should be made, but for testing it is okay
    secretKey_a = random.randint(2, (largePrime_p-1))
    A = pow(generatorOfGroup_g, secretKey_a, largePrime_p)
    pk = (largePrime_p, generatorOfGroup_g, A)
    return pk, secretKey_a

def el_encrypt(pk, message_m):
    ephemeralKey_k = random.randint(1, (pk[0]-1))
    c1 = pow(pk[1], ephemeralKey_k, pk[0])
    c2 = message_m * pow(pk[2], ephemeralKey_k, pk[0])
    return (c1, c2)

def el_decrypt(pk, secretKey_a, ciphertext):
    c1Star = pow(ciphertext[0], (pk[0] - secretKey_a - 1), pk[0])
    message = c1Star * ciphertext[1] % pk[0]

    print(f"Message is from encrypted message : {message}")

# pk, sk = el_setup()
# ciphertext = el_encrypt(pk, 2920)
# el_decrypt(pk, sk, ciphertext)