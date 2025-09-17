import random

def get_generator(p: int):
    while True:
        generator = random.randrange(3, p)
        if pow(generator, 2, p) == 1:
            continue
        if pow(generator, p, p) == 1:
            continue
        return generator

# def is_generator(g, p):
#     roof = p - 1  # The size of the multiplicative group
#     factors = []  # Prime factors of roof

#     # get roof's prime factors
#     n = roof
#     i = 2
#     while i * i <= n:
#         if n % i == 0:
#             factors.append(i)
#             while n % i == 0:
#                 n //= i
#         i += 1
#     if n > 1:
#         factors.append(n)

#     # print(factors)
    
#     # check if 
#     # g^(roof/q) mod p must NOT equal 1 for ANY prime factor q
#     for q in factors:
#         if pow(g, roof // q, p) == 1:
#             return False  # g fails, doesnt have a set going from 1 to p-1
#     return True  # g passes, full cycle, meaning set {1, 2, ... ,p - 1} but dont have to be in that order

# # TODO optimize this function, it is very slow for large p
# def get_highest_generator(p):
#     for g in range(p - 1, 1, -1):  # Start from p-1, and then going backwards
#         if is_generator(g, p):
#             return g
#     return None # bad g

# # Showing a generater that have set going from 1 to p-1
# def show_cycle(g, p):
#     print(f"\nCycle for g = {g} (mod {p}):")
#     value = 1
#     sequence = []
#     for power in range(1, p):
#         oldValue = value
#         value = (value * g) % p
#         sequence.append(value)
#         print(f"g^{power} = {oldValue} * {g} mod {p} = {value}")
#     print(f"\nFull sequence: {sequence}")
#     print(f"Cycle length = {len(sequence)}")


# def example():
#     p = 9
#     highest_g = get_highest_generator(p)
#     print(f"Prime p = {p}")
#     print(f"Highest possible generator g = {highest_g}")

#     # Show the full cycle for this g
#     show_cycle(highest_g, p)

# example()

