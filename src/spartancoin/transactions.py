"""
This module handles transactions

Bitcoin uses ec.SECP256K1 for its EC curve.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, field
from itertools import chain
from typing import Collection

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def encode_varint(i: int) -> bytes:
    """
    Encode a variable-length integer in little endian as per
    https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
    """
    if i < 0:
        raise ValueError(f"invalid: {i!r}")
    if i < 0xFD:
        return i.to_bytes(1, byteorder="little")
    if i <= 0xFFFF:
        return b"\xFD" + i.to_bytes(2, byteorder="little")
    if i <= 0xFFFF_FFFF:
        return b"\xFE" + i.to_bytes(4, byteorder="little")
    if i <= 0xFFFF_FFFF_FFFF_FFFF:
        return b"\xFF" + i.to_bytes(8, byteorder="little")
    raise ValueError(f"invalid: {i!r}")


@dataclass
class Tx:
    """
    An object representing a transmitting input.

    Transmitter layout modified from https://en.bitcoin.it/wiki/Transaction#General_format_.28inside_a_block.29_of_each_input_of_a_transaction_-_Txin
        Field                                     | Size
        -------------------------------------------------------------------------
        Previous Transaction hash (0 if Genesis)  | 32 bytes
        Previous Tx-index (-1 if Genesis)         | 4 bytes
        length of next two fields                 | 1 to 9 bytes VarInt
        signature                                 | 64 bytes
        public key to verify signature            | <2*previous field> - 64 bytes
        sequence_no (not implemented)             | 4 bytes
    """

    prev_tx_hash: bytes
    prev_tx_idx: int
    sender_private_key: InitVar[ec.EllipticCurvePrivateKey]
    signature: bytes = field(init=False)

    def __post_init__(self, sender_private_key: ec.EllipticCurvePrivateKey) -> None:
        if not len(self.prev_tx_hash) == 32:
            raise ValueError("Previous has must be 32 bytes")
        if self.prev_tx_idx == -1:
            # special case for genesis blocks;
            # serialized as unsigned so "overflow" with 4 bytes
            self.prev_tx_idx = 0xFFFF_FFFF
        self.signature = sender_private_key.sign(
            self.prev_tx_hash, ec.ECDSA(hashes.SHA256())
        )
        self.public_key = sender_private_key.public_key()

    def encode(self) -> bytes:
        """Serialize the transmitter"""
        encoded_public_key = self.public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return b"".join(
            [
                self.prev_tx_hash,
                self.prev_tx_idx.to_bytes(4, byteorder="little"),
                encode_varint(len(self.signature) + len(encoded_public_key)),
                self.signature,
                encoded_public_key,
            ]
        )
