from eth_utils import (
    keccak,
    blake2b
)


def public_key_bytes_to_address(public_key_bytes: bytes) -> bytes:
    return bytes.fromhex('a0') + blake2b(public_key_bytes, digest_size=32)[1:32]
