import hashlib

print("\n\n======================start\n")

# parameters
p = 23  # prime number from Z_p*
q = 11  # order of subgroup (q divides p-1)
g = 2   # generator of subgroup of order q in Z_p*

# message in bytes because python's hashlib works with bytes
original_msg = b'hey'
print(f"Bob's original message: '{original_msg.decode()}'")

# Bob's Private/Public keys
print("Bob's key generation:")
x = 7  # private key (is randomly chosen in the range [1, q-1])
y = pow(g, x, p)  # public key (is computed as g^x mod p)
print(f"x = Private key = {x}")
print(f"y = Public key = g^x mod p = {g}^{x} mod {p} = {y}")
print(f"Bob shares his public key (y = {y}) with Alice\n")

# hashing function
def H(val):
	# simple hash: sha256, output as integer mod q
	hash_hex = hashlib.sha256(val).hexdigest()
	hash_int = int(hash_hex, 16)
	hash_mod_q = hash_int % q
	print(f"Hex code from message: {hash_hex}")
	print(f"Numerical value of hex: {hash_int}")
	print(f"Numerical value mod q: {hash_mod_q}")
	return hash_mod_q

# signing
def schnorr_sign(msg):
	print("Bob signing the message:")
	print(f"Message to sign: '{msg.decode()}'")
	
	k = 3 # should be randomized and unique for each signature
	print(f"Random nonce (k) = {k}")
	
	r = pow(g, k, p) # ephemeral key (so r = g^k mod p = 2^3 mod 23 = 8)
	print(f"Ephemeral key (r) = g^k mod p = {g}^{k} mod {p} = {r}")
	
	e = H(msg + str(r).encode()) # hash of message and r
	print(f"Hashes message and ephemeral key (e) = {e}")
	
	s = (k + x * e) % q # signature (s = 3 + 7 * 10 mod 11 = 7)
	print(f"Response (s) = (k + x*e) mod q = ({k} + {x}*{e}) mod {q} = {s}")
	print(f"Signature created: (e={e}, s={s})\n")
	
	return (e, s)

# verification
def schnorr_verify(msg, signature):
	print("Alice verifying the signature:")
	print(f"Received message: '{msg.decode()}'")
	
	e, s = signature # gets the signature components
	print(f"Received signature: (e={e}, s={s})")
	print(f"Bob's public key: y = {y}")
	
	y_inv = pow(y, -e, p) # compute y^{-e} mod p (inverse calculation)
	print(f"Calculate inverse with y^(-e) mod p = {y}^(-{e}) mod {p} = {y_inv}")
	
    # TODO study the proof more. This is apparently like a zero knowledge proof
	# zero knowledge proofs needs to have Completeness, Soundness, and Zero-knowledge
	r_prime = (pow(g, s, p) * y_inv) % p # compute r' = g^s * y^{-e} mod p
	print(f"Calculate the commit value  r' = g^s * y^(-e) mod p = {g}^{s} * {y_inv} mod {p} = {r_prime}") # mathematical proof for this to verify bobs signature without ever knowing bobs private key
	
	e_prime = H(msg + str(r_prime).encode()) # hash of message and r'
	print(f"Hash challenge (e') = {e_prime}")
	
	is_valid = e == e_prime
	print(f"Verification: e == e' ? {e} == {e_prime} ? {is_valid}")
	
	if is_valid:
		print("\nSignature valid. Alice accepts the message.\n")
	else:
		print("\nSignature invalid. Alice rejects the message.\n")
	
	return is_valid

# Message transmission
print("Transmission phase:")
print("Bob signs his message and sends it to Alice...\n")

# Bob signs the message
signature = schnorr_sign(original_msg)

print("Sending to Alice:")
print(f"Original message: '{original_msg.decode()}'")
print(f"Signature: {signature}")
print(f"Bob's public key: {y}")
print(f"Sent over the network...\n")

print("Alice receives:")
print(f"Message: '{original_msg.decode()}'")
print(f"Signature: {signature}")
print(f"Sender's public key: {y}")
print("Alice now verifies the signature...\n")

# Alice verifies the signature
verification_result = schnorr_verify(original_msg, signature)

print("Final result:")
if verification_result:
    print(f"Authentication and integrity with the message: '{original_msg.decode()}'")
else:
    print(f"Verification failed")

print("\n======================End")