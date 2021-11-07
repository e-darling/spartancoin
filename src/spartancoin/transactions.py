"""
This module handles transactions.

The naming conventions for `decode` and `raw_decode` functions are that `decode`
functions take `bytes` objects expecting a single object while `raw_decode`
takes `BytesIO` objects take from the stream as they parse, possibly leaving
extra characters in the stream.
"""

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from typing import cast, Collection

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .exceptions import DecodeError


def encode_varint(i: int) -> bytes:
    r"""
    Encode a variable-length integer in little endian as per
    https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer

    >>> encode_varint(252)
    b'\xfc'
    >>> encode_varint(255)
    b'\xfd\xff\x00'
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


def _assert_read(b: BytesIO, n: int) -> bytes:
    """Read and assert length"""
    d = b.read(n)
    if len(d) != n:
        raise DecodeError(f"Expecting length {n:d}")
    return d


def decode_varint(b: bytes) -> int:
    r"""
    Decode a variable-length integer in little endian as per
    https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer

    >>> decode_varint(b"\xfc")
    252
    >>> decode_varint(b"\xfd\xff\x00")
    255
    """
    d = BytesIO(b)
    n = raw_decode_varint(d)
    if d.read(1):
        # have already parsed the varint, but there are still things after it
        raise DecodeError("Extra data")
    return n


def raw_decode_varint(b: BytesIO) -> int:
    r"""
    Decode (raw) a variable-length integer in little endian as per
    https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer

    >>> b = BytesIO(b"\xfc\xff")
    >>> raw_decode_varint(b)
    252
    >>> b.read()
    b'\xff'
    """
    sentinel = _assert_read(b, 1)
    if sentinel < b"\xFD":
        return int.from_bytes(sentinel, byteorder="little")
    if sentinel == b"\xFD":
        d = _assert_read(b, 2)
    elif sentinel == b"\xFE":
        d = _assert_read(b, 4)
    else:  # sentinel == b"\xFF":
        d = _assert_read(b, 8)
    return int.from_bytes(d, byteorder="little")


def _decode_public_key(b: bytes) -> ec.EllipticCurvePublicKey:
    """Decode a public key from its encoded representation"""
    # `load_der_public_key` returns `DSAPublicKey | EllipticCurvePublicKey | ...`
    return cast(ec.EllipticCurvePublicKey, serialization.load_der_public_key(b))


@dataclass
class Sender:
    """
    An object representing a transmitting input.

    Transmitter layout modified from https://en.bitcoin.it/wiki/Transaction#General_format_.28inside_a_block.29_of_each_input_of_a_transaction_-_Txin
        Field                                     | Size
        -------------------------------------------------------------------------
        Previous Transaction hash (0 if Genesis)  | 32 bytes
        Previous Sender-index (-1 if Genesis)     | 4 bytes
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
        if not isinstance(other, Sender):
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
            f"Sender({self.prev_tx_hash}, {self.prev_tx_idx}, "
            f"{self.signature}, {self.public_key})"
        )

    @classmethod
    def from_prk(
        cls,
        prev_tx_hash: bytes,
        prev_tx_idx: int,
        sender_private_key: ec.EllipticCurvePrivateKey,
    ) -> Sender:
        """Create a `Sender` from the sender's private key."""
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
    def decode(cls, b: bytes) -> Sender:
        """Decode a `Sender` from the encoded bytes"""
        d = BytesIO(b)
        sender = cls.raw_decode(d)
        if d.read(1):
            # have already parsed, but there are still things after it
            raise DecodeError("Extra data")
        return sender

    @classmethod
    def raw_decode(cls, b: BytesIO) -> Sender:
        """Decode (raw) a `Sender` from the encoded bytes"""
        prev_tx_hash = _assert_read(b, 32)
        prev_tx_idx = int.from_bytes(_assert_read(b, 4), byteorder="little")
        len_of_next_two = raw_decode_varint(b)
        signature = _assert_read(b, len_of_next_two - 88)
        public_key = _decode_public_key(_assert_read(b, 88))
        return cls(prev_tx_hash, prev_tx_idx, signature, public_key)


@dataclass
class Receiver:
    """
    An object representing a receiving block.

    Receiver layout modified from https://en.bitcoin.it/wiki/Transaction#General_format_.28inside_a_block.29_of_each_output_of_a_transaction_-_Txout
        Field                 | Size
        ----------------------------------------------
        amount                | 8 bytes
        length of next field  | 1 to 9 bytes VarInt
        Receiver-PubKey       | <previous field> bytes
    """

    amount: int
    recipient: ec.EllipticCurvePublicKey

    def __eq__(self, other):
        if not isinstance(other, Receiver):
            return NotImplemented
        return (
            self.amount == other.amount
            # `self.public_key == other.public_key` does not work
            and self.recipient.public_numbers() == other.recipient.public_numbers()
        )

    def __repr__(self):
        return f"Receiver({self.amount}, {self.recipient})"

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
    def decode(cls, b: bytes) -> Receiver:
        """Decode a `Receiver` from the encoded bytes"""
        d = BytesIO(b)
        sender = cls.raw_decode(d)
        if d.read(1):
            # have already parsed, but there are still things after it
            raise DecodeError("Extra data")
        return sender

    @classmethod
    def raw_decode(cls, b: BytesIO) -> Receiver:
        """Decode (raw) a `Receiver` from the encoded bytes"""
        amount = int.from_bytes(_assert_read(b, 8), byteorder="little")
        len_of_public_key = raw_decode_varint(b)
        public_key = _decode_public_key(_assert_read(b, len_of_public_key))
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

    senders: Collection[Sender]
    receivers: Collection[Receiver]

    def __eq__(self, other):
        if not isinstance(other, Transaction):
            return NotImplemented
        return self.senders == other.senders and self.receivers == other.receivers

    def encode(self) -> bytes:
        """Serialize the transaction"""
        return b"".join(
            [
                b"\x01\x00\x00\x00",  # version 1 in little endian
                encode_varint(len(self.senders)),
                *[tx.encode() for tx in self.senders],
                encode_varint(len(self.receivers)),
                *[rx.encode() for rx in self.receivers],
            ]
        )

    @classmethod
    def decode(cls, b: bytes) -> Transaction:
        """Decode a `Transaction` from the encoded bytes"""
        d = BytesIO(b)
        sender = cls.raw_decode(d)
        if d.read(1):
            # have already parsed, but there are still things after it
            raise DecodeError("Extra data")
        return sender

    @classmethod
    def raw_decode(cls, b: BytesIO) -> Transaction:
        """Decode (raw) a `Receiver` from the encoded bytes"""
        _version_number = int.from_bytes(_assert_read(b, 4), byteorder="little")
        assert _version_number == 1, "version number is unused but should be 1"

        n_senders = raw_decode_varint(b)
        senders = [Sender.raw_decode(b) for _ in range(n_senders)]
        n_receivers = raw_decode_varint(b)
        receivers = [Receiver.raw_decode(b) for _ in range(n_receivers)]
        return cls(senders, receivers)
