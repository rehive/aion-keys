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
    v, R, S = signature
    signature_bytes = int_to_big_endian(R) + int_to_big_endian(S)
    if not v == 1:
        raise Exception("Bad Signature")
    verify_key = VerifyingKey(public_key)
    return verify_key.verify(msg_hash, signature_bytes)


def ecdsa_raw_recover(msg_hash: bytes,
                      vrs: Tuple[int, int, int]) -> bytes:
    raise NotImplementedError("ED25519 does not allow you to recover the "
                              "public key from the signature and msg_hash")


def ecdsa_raw_sign(msg_hash: bytes,
                   private_key_bytes: bytes) -> Tuple[int, int, int]:
    private_key = SigningKey(private_key_bytes)
    signature_bytes = private_key.sign(msg_hash)
    R = big_endian_to_int(signature_bytes[:32])
    S = big_endian_to_int(signature_bytes[32:])
    return 1, R, S


def private_key_to_public_key(private_key_bytes: bytes) -> bytes:
    private_key = SigningKey(private_key_bytes)
    return private_key.get_verifying_key().to_bytes()
