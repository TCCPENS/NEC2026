from hashlib import sha512
from Crypto.Util.number import isPrime, bytes_to_long
from math import gcd
import secrets

FLAG = b"NEC{REDACTED}"

MASK = (1 << 128) - 1


def weak_random(seed):
    x = seed

    x ^= x >> 23
    x ^= (x << 41) & MASK

    return x & MASK


def prime_from_seed(seed, label):
    seed_bytes = seed.to_bytes(16, "big")

    raw = sha512(
        label + seed_bytes
    ).digest()

    candidate = int.from_bytes(raw, "big")

    # Paksa menjadi 512-bit dan odd
    candidate |= (1 << 511)
    candidate |= 1

    while not isPrime(candidate):
        candidate += 2

    return candidate


seed = secrets.randbits(128)

p = prime_from_seed(seed, b"P")
q = prime_from_seed(seed, b"Q")

assert p != q

n = p * q
phi = (p - 1) * (q - 1)

e = 65537

assert gcd(e, phi) == 1

m = bytes_to_long(FLAG)

assert m < n

c = pow(m, e, n)

leak = weak_random(seed)

print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")
print(f"leak = {leak}")
