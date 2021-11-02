"""
This module handles transactions

Bitcoin uses ec.SECP256K1 for its EC curve.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast, Collection

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .exceptions import DecodeError


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


def _assert_is_len(b: bytes, n: int) -> None:
    if len(b) != n:
        raise ValueError(f"Expecting length {n:d}")


def decode_varint(b: bytes) -> int:
    """
    Decode a variable-length integer in little endian as per
    https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
    """
    if not b:
        raise ValueError("empty bytes")
    sentinel = b[0]
    if sentinel < 0xFD:
        _assert_is_len(b, 1)
        return int.from_bytes(b, byteorder="little")
    if sentinel == 0xFD:
        _assert_is_len(b[1:], 2)
    elif sentinel == 0xFE:
        _assert_is_len(b[1:], 4)
    else:  # sentinel == 0xFF:
        _assert_is_len(b[1:], 8)
    return int.from_bytes(b[1:], byteorder="little")


def _decode_public_key(b: bytes) -> ec.EllipticCurvePublicKey:
    """Decode a public key from its encoded representation"""
    # `load_der_public_key` returns `DSAPublicKey | EllipticCurvePublicKey | ...`
    return cast(ec.EllipticCurvePublicKey, serialization.load_der_public_key(b))


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
        signature                                 | <previous field> bytes - 88
        public key to verify signature            | 88 bytes
    """

    prev_tx_hash: bytes
    prev_tx_idx: int
    signature: bytes
    public_key: ec.EllipticCurvePublicKey

    def __post_init__(self) -> None:
        if not len(self.prev_tx_hash) == 32:
            raise ValueError("Previous has must be 32 bytes")
        if self.prev_tx_idx == -1:
            # special case for genesis blocks;
            # serialized as unsigned so "overflow" with 4 bytes
            self.prev_tx_idx = 0xFFFF_FFFF

    def __eq__(self, other):
        if not isinstance(other, Tx):
            return NotImplemented
        return (
            self.prev_tx_hash == other.prev_tx_hash
            and self.prev_tx_idx == other.prev_tx_idx
            and self.signature == other.signature
            # `self.public_key == other.public_key` does not work
            and self.public_key.public_numbers() == other.public_key.public_numbers()
        )

    def __repr__(self):
        return (
            f"Tx({self.prev_tx_hash}, {self.prev_tx_idx}, "
            f"{self.signature}, {self.public_key})"
        )

    @classmethod
    def from_prk(
        cls,
        prev_tx_hash: bytes,
        prev_tx_idx: int,
        sender_private_key: ec.EllipticCurvePrivateKey,
    ) -> Tx:
        """Create a `Tx` from the sender's private key."""
        signature = sender_private_key.sign(prev_tx_hash, ec.ECDSA(hashes.SHA256()))
        public_key = sender_private_key.public_key()
        return cls(prev_tx_hash, prev_tx_idx, signature, public_key)

    def encode(self) -> bytes:
        """Serialize the transmitter"""
        encoded_public_key = self.public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        assert len(encoded_public_key) == 88, "this should be consistent"
        return b"".join(
            [
                self.prev_tx_hash,
                self.prev_tx_idx.to_bytes(4, byteorder="little"),
                encode_varint(len(self.signature) + len(encoded_public_key)),
                self.signature,
                encoded_public_key,
            ]
        )

    @classmethod
    def from_bytes(cls, b: bytes) -> Tx:
        """Return a `Tx` from the encoded bytes"""
        if len(b) <= 32 + 4 + 88:
            raise DecodeError("invalid length")
        prev_tx_hash = b[:32]
        prev_tx_idx = int.from_bytes(b[32:36], byteorder="little")
        for n in (1, 3, 5, 9):
            try:
                len_next_two = decode_varint(b[36 : 36 + n])
            except ValueError:
                continue
            else:
                break
        else:
            raise DecodeError("invalid varint")
        if len(b[36 + n :]) != len_next_two:
            raise DecodeError("invalid length")
        signature = b[36 + n : 36 + n + len_next_two - 88]
        public_key = _decode_public_key(b[36 + n + len_next_two - 88 :])
        return cls(prev_tx_hash, prev_tx_idx, signature, public_key)


@dataclass
class Rx:
    """
    An object representing a receiving block.

    Receiver layout modified from https://en.bitcoin.it/wiki/Transaction#General_format_.28inside_a_block.29_of_each_output_of_a_transaction_-_Txout
        Field                 | Size
        ----------------------------------------------
        amount                | 8 bytes
        length of next field  | 1 to 9 bytes VarInt
        Rx-PubKey             | <previous field> bytes
    """

    amount: int
    recipient: ec.EllipticCurvePublicKey

    def __eq__(self, other):
        if not isinstance(other, Rx):
            return NotImplemented
        return (
            self.amount == other.amount
            # `self.public_key == other.public_key` does not work
            and self.recipient.public_numbers() == other.recipient.public_numbers()
        )

    def __repr__(self):
        return f"Rx({self.amount}, {self.recipient})"

    def encode(self) -> bytes:
        """Serialize the receiver"""
        encoded_public_key = self.recipient.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return b"".join(
            [
                self.amount.to_bytes(8, byteorder="little"),
                encode_varint(len(encoded_public_key)),
                encoded_public_key,
            ]
        )

    @classmethod
    def from_bytes(cls, b: bytes) -> Rx:
        """Serialize the receiver"""
        if len(b) <= 8 + 1 + 1:
            raise DecodeError("invalid length")
        amount = int.from_bytes(b[:8], byteorder="little")
        for n in (1, 3, 5, 9):
            try:
                len_puk = decode_varint(b[8 : 8 + n])
            except ValueError:
                continue
            else:
                break
        else:
            raise DecodeError("invalid varint")
        if len(b[8 + n :]) != len_puk:
            raise DecodeError("invalid length")
        public_key = _decode_public_key(b[8 + n :])
        return cls(amount, public_key)


@dataclass
class Transaction:
    """
    A transaction that spends the entirety of the transmitted coins
    to a collection of recipients.

    From the whitepaper:
        Although it would be possible to handle coins individually, it would be
        unwieldy to make a separate transaction for every cent in a transfer.
        To allow value to be split and combined, transactions contain multiple
        inputs and outputs. Normally there will be either a single input from a
        larger previous transaction or multiple inputs combining smaller amounts,
        and at most two outputs: one for the payment, and one returning the
        change, if any, back to the sender.

    So, to spend only a part of a coin, a transaction is made from A to A and B,
    where A receives the "unspent" amount and B receives the "spent" amount.

    Transaction layout modified from https://en.bitcoin.it/wiki/Transaction#General_format_of_a_Bitcoin_transaction_.28inside_a_block.29
        Field                             | Size
        ---------------------------------------------
        version number                    | 4 bytes
        number of inputs                  | 1 to 9 bytes VarInt
        list of inputs                    | varies
        number of outputs                 | 1 to 9 bytes VarInt
        list of outputs                   | varies
    """

    txs: Collection[Tx]
    rxs: Collection[Rx]

    def encode(self) -> bytes:
        """Serialize the transaction"""
        return b"".join(
            [
                b"0001",  # version 1
                encode_varint(len(self.txs)),
                *[tx.encode() for tx in self.txs],
                encode_varint(len(self.rxs)),
                *[rx.encode() for rx in self.rxs],
            ]
        )
