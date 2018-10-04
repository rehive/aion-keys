from __future__ import absolute_import

from typing import Optional  # noqa: F401

from .ed25519 import (
    ecdsa_raw_recover,
    ecdsa_raw_sign,
    ecdsa_verify,
    private_key_to_public_key,
)

from eth_keys.backends.base import BaseECCBackend
from eth_keys.datatypes import (  # noqa: F401
    PrivateKey,
    PublicKey,
    Signature,
)


class TwistedEdwardsECCBackend(BaseECCBackend):
    def ecdsa_sign(self,
                   msg_hash: bytes,
                   private_key: PrivateKey) -> Signature:
        signature_bytes = ecdsa_raw_sign(msg_hash, private_key.to_bytes())
        signature = Signature(signature_bytes=signature_bytes, backend=self)
        return signature

    def ecdsa_verify(self,
                     msg_hash: bytes,
                     signature: Signature,
                     public_key: PublicKey) -> bool:
        public_key_bytes = public_key.to_bytes()
        return ecdsa_verify(msg_hash, signature.vrs, public_key_bytes)

    def ecdsa_recover(self,
                      msg_hash: bytes,
                      signature: Signature) -> PublicKey:
        public_key_bytes = ecdsa_raw_recover(msg_hash, signature.vrs)
        public_key = PublicKey(public_key_bytes, backend=self)
        return public_key

    def private_key_to_public_key(self, private_key: PrivateKey) -> PublicKey:
        public_key_bytes = private_key_to_public_key(private_key.to_bytes())
        public_key = PublicKey(public_key_bytes, backend=self)
        return public_key
