from hashlib import blake2b as BLAKE2B

from typing import (Any, Tuple,)  # noqa: F401
#
# From http://github.com/vbuterin/ed25519/blob/master/ed25519.py
# http://ed25519.cr.yp.to/ed25519-20110926.pdf
#
# Known issues: http://github.com/vbuterin/ed25519/issues


from eth_keys.constants import (
    ED25519_Q as Q,
    ED25519_B as B,
    ED25519_Bx as Bx,
    ED25519_By as By,
    ED25519_D as D,
    ED25519_L as L,
    ED25519_BITS as BITS,
)

from eth_utils import (
    int_to_big_endian,
    big_endian_to_int,
)

from .edwards import (
    inv,
    modular_sqrt,
    is_on_curve,
    add,
    fast_multiply,
)

def blake2b(msg_hash: bytes) -> bytes:
    return BLAKE2B(msg_hash).digest()


# Standard-form encoding for a public key
def encode_raw_public_key(raw_public_key: Tuple[int, int]) -> bytes:
    left, right = raw_public_key
    if left > Q - left:
        right |= 2**255
    return int_to_big_endian(right)


def x_from_y(y):
    # -x^2 + y^2 = 1 + d * x^2 * y^2
    # implies
    # (y^2 - 1) / (d * y^2 + 1) = x^2
    nom = (y*y-1) % Q
    den = (D*y*y+1) % Q
    return modular_sqrt((nom * inv(den, Q)) % Q, Q)


def decode_public_key(public_key_bytes: bytes) -> Tuple[int, int]:
    v = big_endian_to_int(public_key_bytes)
    right = v % 2**255
    left = x_from_y(right)
    if (left > Q - left) ^ (v >> 255):
        left = Q - left
    return (left, right)


def privtopub(k):
    h = blake2b(k)
    a = 2 ** (BITS - 2) + (big_endian_to_int(h[:32]) % 2 ** (BITS - 2))
    a -= (a % 8)
    return fast_multiply(B, a)


# Signature algorithm
def sign(k, m):
    h = blake2b(k)
    a = 2 ** (BITS - 2) + (big_endian_to_int(h[:32]) % 2 ** (BITS - 2))
    a -= (a % 8)
    A = fast_multiply(B, a)
    r = big_endian_to_int(h[32:])
    R = fast_multiply(B, r)
    h2 = blake2b(encode_raw_public_key(R) + encode_raw_public_key(A) + m)
    s = (r + big_endian_to_int(h2) * a) % L
    return encode_raw_public_key(R) + int_to_big_endian(s)


# Verification algorithm
def verify(pub, sig, m):
    R = decode_public_key(sig[:32])
    s = big_endian_to_int(sig[32:])
    if s >= L:
        return False
    A = encode_raw_public_key(pub)
    h2 = blake2b(sig[:32] + A + m)
    assert is_on_curve(R)
    return fast_multiply(B, 8 * s) == add(fast_multiply(R, 8), fast_multiply(pub, 8 * big_endian_to_int(h2)))


def ecdsa_raw_recover(msg_hash: bytes,
                      vrs: Tuple[int, int, int]) -> bytes:
    raise Exception("Not Implemented")


def ecdsa_raw_sign(msg_hash: bytes,
                   private_key_bytes: bytes) -> Tuple[int, int, int]:
    raise Exception("Not Implemented")


def private_key_to_public_key(private_key_bytes: bytes) -> bytes:
    raise Exception("Not Implemented")
