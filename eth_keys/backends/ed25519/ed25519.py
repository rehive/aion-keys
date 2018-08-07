from hashlib import blake2b as BLAKE2B

from typing import (Any, Tuple,)  # noqa: F401
#
# From http://github.com/vbuterin/ed25519/blob/master/ed25519.py
# http://ed25519.cr.yp.to/ed25519-20110926.pdf
#
# Known issues: http://github.com/vbuterin/ed25519/issues

from ed25519 import (
    SigningKey,
    VerifyingKey,
)

from eth_utils import (
    int_to_big_endian,
    big_endian_to_int,
)

# Verification algorithm
def ecdsa_verify(msg_hash: bytes,
                 signature: Tuple[int, int, int],
                 public_key: bytes) ->bool:
    R = (signature[0], signature[1],)
    s = signature[2]
    if s >= L:
        return False
    h2 = blake2b( encode_raw_public_key(R) + public_key + msg_hash)
    assert is_on_curve(R)
    v = add(
        fast_multiply(R, 8),
        fast_multiply(public_key, 8 * big_endian_to_int(h2))
    )
    return bool(fast_multiply(B, 8 * s) == v)


def ecdsa_raw_recover(msg_hash: bytes,
                      vrs: Tuple[int, int, int]) -> bytes:
    raise NotImplementedError("ED25519 does not allow you to recover the "
                              "public key from the signature and msg_hash")


def ecdsa_raw_sign(msg_hash: bytes,
                   private_key_bytes: bytes) -> Tuple[int, int, int]:
    h = blake2b(private_key_bytes)
    a = 2 ** (BITS - 2) + (big_endian_to_int(h[:32]) % 2 ** (BITS - 2))
    a -= (a % 8)
    A = fast_multiply(B, a)
    r = big_endian_to_int(h[32:])
    R = fast_multiply(B, r)
    h2 = blake2b(encode_raw_public_key(R) + encode_raw_public_key(A) + msg_hash)
    s = (r + big_endian_to_int(h2) * a) % L
    return R[0], R[1], s


def private_key_to_public_key(private_key_bytes: bytes) -> bytes:
    h = blake2b(private_key_bytes)
    a = 2 ** (BITS - 2) + (big_endian_to_int(h[:32]) % 2 ** (BITS - 2))
    a -= (a % 8)
    raw_public_key = fast_multiply(B, a)
    public_key_bytes = encode_raw_public_key(raw_public_key)
    return public_key_bytes
