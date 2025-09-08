# Step by step Schnorr's algorithm
Following ./algorithms/schnorr.py programming and math examples

## Quick Overview
1. **Setup**: Choose parameters p, q, g and generate key pair (x, y)
2. **Signing**: Create signature (e, s) using message, nonce k, and private key x  
3. **Verification**: Reconstruct r' and verify e' = e

# Parameters

### p (prime number)
p is chosen from the multiplicaple group of Z_p*

### q (subgroup of p)
q is chosen from the subgroup of p, this means: 

<ul>
    <li>q must divide (p-1).</li>
    <li>q is the size of a smaller subgroup within Z_p*.</li>
    <li>It follows Lagranges theorem, that in any group, the size of any subgroup must divide the size of the whole group.</li>
    <li>Choose q to be the larges prime factor of p-1</li>
</ul>

### g (generated)
g must not be 1 and has to take the "full round" of numbers when going through Z_p*. I.e
Pick a number 'h' from Z_p* {2,3,4... 22} and start caclculating g = h^((p-1)/q) mod p.
For instance, 2 works directly because 2^11 ≡ 1 (mod 23).


### x (private key)
private key is chosen randomly in the range {1 ... q-1}. So in our case x are one of these choices {1, 2, 3, 4, 5, 6, 7, 8, 9, 10}


## Parameter examples

### p (prime number)
p = 23:

Z_23* = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22}

### q (subgroup of p)
q = 11

<ol>
    <li>p - 1 = 23 - 1 = 22</li>
    <li>in Z_p* what numbers divide 22? {1, 2, 11, 22}.</li>
    <li>Which number do we choose? one of the highest since lower numbers are more insecure. 11 is the best match here for optimal security. But why not 22? It contains small factors like 2*11, which is lower security too apparently</li>
</ol>

### g (generated)
we know that: p = 23, q = 11 and we have chosen that h = 2 (random chosen number thats not 1)

Now we calculate g = h^((p-1)/q) mod p.

The integer '2' works, since it can go the "full round" of 11 elements before repeating (already seen this example on blackboard, notes github)
'4' is another that would work for g.

### x (private key)
x = 7

this was chosen randomly from the range {1 ... q-1} (remember q is 11)

# Hashing

Why is the hashing even needed? Because it prevents forgery and ensures message integrity.

The Schnorr signatures use Fiat-Shamir heuristic to convert an interactive zero-knowledge proofs into a non-interactive signature scheme.

#### without hashing an attacker could
<ul>
<li>Pick any s and e</li>
<li>Compute r' = g^s * y^(-e) mod p</li>
<li>Claim this is a valid signature for any message</li>
</ul>

#### with hashing an attacker cannot
<ul>
<li>Choose e freely (it's determined by the hash)</li>
<li>The hash creates a "random oracle" that they cannot control</li>
</ul>

### hashing with challenge
the hashing binds the challenge (epheremal key), with both the message and the commitment r = g^k mod p. This prevents forgery even further.

## Hashing calculations
from coding example in schnorr.py
<ol>
<li>First convert message to hex code using sha256</li>
<li>Hex code from message: ef98cd686d1cad7744551007b77715d33e424fab1975edd8356ed1d23a745c4e</li>
<li>now convert hex into integer</li>
<li>Numerical value of hex: 108372749238573363761270345913201371466881101674911690443957810710438403660878</li>
<li>Now mod that number using q (which is 11 in our case)</li>
<li>e = 10</li>
</ol>

# Signing

### k (nonce)
k is chosen randomly and is unique for each signing, it is chosen the same way x (private key) is chosen, [1, q-1]. i.e. k is one of {1, 2, 3, 4, 5, 6, 7, 8, 9, 10}. k is called the nonce (as it is always unique).

### r (ephemeral key)
r is the ephemeral key and is calculated from r = g^k mod p
r = 2^3 mod 23 = 8

### e (hashing the message and r)
to find e, we hash it the message itself and r like so.
<ol>
<li>msg = b'hey' (message in bytes)</li>
<li>r = 8 (ephemeral key from r = 2^3 mod 23)</li>
<li>str(r).encode() = '8'.encode() = b'8'</li>
<li>concatinate it so its msg + str(r).encode() = b'hey' + b'8' = b'hey8'</li>
<li>hash the 'hey8' which produces a hex string</li>
<li>the hash string is converted to integer with hash_int</li>
<li>now reduce the hash_int with modulo q, i.e., hash_int % 11</li>
</ol>

### s (signature)
s is just a calculation: s = (k + x * e) % q = (3 + 7 * e) % 11
now s contains k, x and e inside of it.

## signing example
g = 2

k = 3

r = g^k mod p = 2^3 mod 23 = 8

e = 10

calculate s:

s = (k + x * e) % q = (3 + 7 * 10) % 11 = 7

we send (e, s) to alice

return (10, 7)

# Verification

ok, alice receives the following from bob

<ul>
<li>Message: "hey"</li>
<li>Signature: (e, s)</li>
<li>Bob's public key: y</li>
</ul>

now calculate to see if the signature is valid

## inverse
compute the modular multiplicative inverse of y^e

### y_inv (inverse example calculation)
<ol>
<li>y = 18 (Bob's public key = g^x mod p = 2^7 mod 23)</li>
<li>e = 10</li>
<li>p = 23</li>
<li>the calculation for inverse: y_inv = 18^(-10) mod 23 = 1</li>
</ol>

We use y_inv to reconstruct r'.

## r' (Zero knowledge proof)
r = 8 so we need r' to be 8 too.

This is the calculation for r'

r' = g^s * y^(-e) mod p

proof:

<ol>
<li><strong>calculation:</strong>            r' = g^s * y^(-e) mod p</li>
<li><strong>Substitute s:</strong>           r' = g^(k + x*e) * y^(-e) mod p</li>
<li><strong>Use exponent rules:</strong>     r' = g^k * g^(x*e) * y^(-e) mod p</li>
<li><strong>Substitute y = g^x:</strong>     r' = g^k * (g^x)^e * (g^x)^(-e) mod p</li>
<li>r' = g^k * g^(x*e) * g^(-x*e) mod p</li>
<li>r' = g^k * g^(x*e - x*e) mod p</li>
<li>r' = g^k * g^0 mod p</li>
<li>r' = g^k * 1 mod p</li>
<li>r' = g^k mod p</li>
<li>r' = g^k mod p = r</li>
<li>Result: r' = r</li>
</ol>

This is a zero knowledge proof, since Alice did not know Bob's private key x, but can calculate the same commitment he made.

## e' (hashing)
now we need to check if alices hash matches bobs original hash, now that we have r' we can hash it, just like bob did

e_prime = H(b'hey' + str(r_prime).encode())

this should be identical to bobs e = H(b'hey' + str(r).encode())

e' == e

if the signatures are valid, then it returns true and is the cryptographic proof...