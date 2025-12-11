from utils.shuffle import Shuffle
from utils.procedures import Procedures

# testing shuffle flow
def test_basic_shuffle():
    """ """
    print("\n" + "="*60)
    print("Testing Basic Shuffle Proof with Real Keys")
    print("="*60)
    pro = Procedures()
    pp = pro.pp
    shuffle = Shuffle(pp=pro.pp)
    g = pp[1]
    N = 5
    
    print(f"\n1. Generating {N} user keys ...")
    users = []
    e = []
    
    for i in range(N):
        user_id = f"User_{i}"
        ((id, (pk, pp_user, proof)), sk) = pro.skey_gen(user_id, pp)
        users.append({
            'id': user_id,
            'pk': pk,
            'sk': sk,
            'proof': proof
        })
        e.append(pk)
        print(f"   {user_id}: pk={str(pk)[:50]}...")
    
    print(f"\n2. Shuffling and anonymizing public keys...")
    e_prime, r_prime, ψ = shuffle.GenShuffle(e) 
    print(f"   Permutation: {ψ}")
    
    print(f"\n3. Generating shuffle proof (πmix)...")
    proof = shuffle.GenProof(e, e_prime, r_prime, ψ, g)
    
    print(f"\n4. Verifying shuffle proof...")
    is_valid = shuffle.verify_shuffle_proof(proof, e, e_prime, g)
    
    print(f"\n{'='*60}")
    print(f"Result: {'✅ PASS' if is_valid else '❌ FAIL'}")
    print(f"{'='*60}\n")
    
    return is_valid


def test_basic_shuffle_pk():
    """ """
    print("\n" + "="*60)
    print("Testing Basic Shuffle Proof with Real Keys")
    print("="*60)
    pro = Procedures()
    pp = pro.pp
    shuffle = Shuffle(pp=pro.pp)
    g = pp[1]
    N = 5
    
    print(f"\n1. Generating {N} user keys ...")
    users = []
    e = []
    
    for i in range(N):
        user_id = f"User_{i}"
        ((id, (pk, pp_user, proof)), sk) = pro.skey_gen(user_id, pp)
        users.append({
            'id': user_id,
            'pk': pk,
            'sk': sk,
            'proof': proof
        })
        e.append(pk)
        print(f"   {user_id}: pk={str(pk)[:50]}...")
    
    print(f"\n2. Shuffling and anonymizing public keys...")
    e_prime, r_prime, ψ = shuffle.GenShuffle(e) 
    print(f"   Permutation: {ψ}")
    
    print(f"\n3. Generating shuffle proof (πmix)...")
    proof = shuffle.GenProof(e, e_prime, r_prime, ψ, g)
    
    print(f"\n4. Verifying shuffle proof...")
    is_valid = shuffle.verify_shuffle_proof(proof, e, e_prime, g)
    
    print(f"\n{'='*60}")
    print(f"Result: {'✅ PASS' if is_valid else '❌ FAIL'}")
    print(f"{'='*60}\n")
    
    return is_valid

def test_integration_with_aggregator():
    """ """
    print("\n" + "="*60)
    print("Testing Full Integration Flow")
    print("="*60)
    pro = Procedures()

    pp = pro.pp
    g = pp[1]
    N = 5
    
    shuffle = Shuffle(pp)
    ID_pk = []
    user_data = {}
    
    for i in range(N):
        user_id = f"A{i}"
        ((id, (pk, pp_user, proof)), sk) = pro.skey_gen(user_id, pp)
        ID_pk.append((user_id, pk))
        user_data[user_id] = {'pk': pk, 'sk': sk}
    
    print(f"\n2. Aggregator mixes public keys...")
    e = [pk for _, pk in ID_pk]
    e_prime, r_prime, ψ = shuffle.GenShuffle(e)
    πmix = shuffle.GenProof(e, e_prime, r_prime, ψ, g)
    
    r_map = {}
    for i, (user_id, original_pk) in enumerate(ID_pk):
        shuffled_pos = ψ.index(i)
        r_map[user_id] = r_prime[i]
    
    print(f"\n3. Verifying shuffle proof...")
    is_valid = shuffle.verify_shuffle_proof(πmix, e, e_prime, g)
    
    print(f"\n4. Users verify they can use anonymized keys...")
    all_verified = True
    for i, (user_id, original_pk) in enumerate(ID_pk):
        r_val = r_map[user_id]
        shuffled_pos = ψ.index(i)
        
        blinding_point = int(r_val) * g
        expected_pk = original_pk + blinding_point
        
        if expected_pk == e_prime[shuffled_pos]:
            print(f"   ✓ {user_id} verified")
        else:
            print(f"   ✗ {user_id} FAILED verification")
            all_verified = False
    
    print(f"\n{'='*60}")
    print(f"Overall: {'✅ PASS' if (is_valid and all_verified) else '❌ FAIL'}")
    print(f"{'='*60}\n")
    
    return is_valid and all_verified

if __name__ == "__main__":
    test_basic_shuffle()
    test_basic_shuffle_pk()
    test_integration_with_aggregator()