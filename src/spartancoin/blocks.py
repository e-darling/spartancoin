"""
Create blocks of transactions
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Sequence

from .transactions import Transaction


def better_hash_args(*args: bytes) -> bytes:
    """
    Function to hash an entire list of bytes into one hash.
    This is more similar to what bitcoin does, but is slower than
    `faster_hash_args`. Bitcoin hashes twice for better security.

    Currently double-hashes SHA-512
    """
    full_bytes = b"".join(args)

    new_hash = hashlib.sha512()
    new_hash.update(full_bytes)
    return_hash = new_hash.digest()
    new_hash2 = hashlib.sha512()
    new_hash2.update(return_hash)
    return_hash = new_hash2.digest()
    return return_hash


def faster_hash_args(*args: bytes) -> bytes:
    """
    Function to hash an entire list of bytes into one hash.
    This is faster than `better_hash_args` since it only hashes once.

    Currently single-hashes SHA-512
    """
    full_bytes = b"".join(args)

    new_hash = hashlib.sha512()
    new_hash.update(full_bytes)
    return new_hash.digest()


# def get_difficulty(diff_index: bytes):
#     """
#     Gets the "number of leading zeroes" from the difficulty index
#     Specified by https://en.bitcoin.it/wiki/Difficulty
#
#     Packed Bits Format:
#     0x1b0404cb
#     <2 bytes exponential position> <6 bytes>
#
#     TODO: Make this work for SHA-512
#     """
#     intified = int.from_bytes(diff_index, byteorder="little")
#     pos = intified >> 24
#     lower_24 = intified & 0xFF_FFFF
#     limit = lower_24 * 2 ** (8 * (pos - 3))
#     limit = limit << 256  # shift left 256 bytes for SHA-512 testing purposes
#     return limit.to_bytes(length=64, byteorder="little")


def leading_0_bits(b: bytes) -> int:
    r"""
    Return the number of leading 0 *bit*s in a *byte*string

    >>> leading_0_bits(b"")
    0
    >>> leading_0_bits(b"\x00\x00")
    16
    >>> leading_0_bits(b"\x00\x00\xf1\x02")
    16
    >>> leading_0_bits(b"\x01\x02")
    7
    >>> leading_0_bits(b"\x00\x02\x01")
    14
    """
    i = 0
    while i < len(b) and b[i] == 0:
        i += 1
    try:
        # usual case is there are more bytes after where we stopped
        return 8 * i + 8 - b[i].bit_length()
    except IndexError:
        # if the bytestring is entirely b"\x00", will reach the end
        return 8 * i


@dataclass
class Block:
    """
    The Block part of the Blockchain

    Information derived from
    https://www.oreilly.com/library/view/mastering-bitcoin/9781491902639/ch07.html

    Adjusted to fit SHA-512's 512-bit output
    Block structure:
        Field                | Size
        ------------------------------------------
        Block size           | 4 bytes
        Block header         | 144 bytes
        Transaction counter  | 1 to 9 bytes VarInt
        Transaction          | variable

    Block header structure:
    (note: this is the only part that is hashed to identify this block)
        Field                | Size
        -------------------------------
        Version              | 4 bytes
        Previous block hash  | 64 bytes
        Merkle root          | 64 bytes
        Timestamp            | 4 bytes
        Difficulty index     | 4 bytes
        Nonce                | 4 bytes
    """

    hash_algorithm = hashlib.sha256

    prev_block_hash: bytes
    transactions: Sequence[Transaction]
    difficulty: int = 1  # target number of bits

    def __post_init__(self) -> None:
        """Generate a Merke Root from the input transactions"""
        self.merkle_root = self.__hash_merkle()
        self.timestamp = int(time.time())  # epoch time
        self.nonce = 0

    @classmethod
    def _hash(cls, *bs: bytes) -> bytes:
        """
        Hash using the class's hashing algorithm.
        """
        full_bytes = b"".join(bs)
        new_hash = cls.hash_algorithm(full_bytes)
        return new_hash.digest()

    def __hash_merkle(self) -> bytes:
        """
        Compute the Merkle Root (binary hash) of every transaction in the block
        using double-SHA-512
        """
        # Hash every transaction individually first then add them to a list
        hashed_transactions = []
        for tran in self.transactions:
            # hash transaction
            tran_bytes = tran.encode()
            new_hash = self._hash(tran_bytes)
            # add to temporary hashed transaction list
            hashed_transactions.append(new_hash)

        # Combine transactions in pairs, as if we were building a balanced binary tree
        num_transactions = len(hashed_transactions)
        while num_transactions > 1:
            counter = 0
            temp_transactions = []
            while counter < ((num_transactions // 2) * 2):
                pair_hash = self._hash(
                    hashed_transactions[counter], hashed_transactions[counter + 1]
                )
                temp_transactions.append(pair_hash)
                counter += 2
            if num_transactions % 2 == 1 and num_transactions > 1:
                lonely_hash = self._hash(hashed_transactions[counter])
                temp_transactions.append(lonely_hash)
            hashed_transactions = temp_transactions
            num_transactions = len(hashed_transactions)
        # at the end, there should only be one hash
        # assign the last remaining hash to merkle_root
        return hashed_transactions[0]

    def hash(self) -> bytes:
        """
        Hash the entire block header as proof that these transactions happened

        @returns a double-SHA-512 hash of this block
        """
        # get difficulty rating
        # get timestamp
        # get merkle root hash
        # get version
        # temp_difficulty = get_difficulty(self.difficulty)
        # the generated hash must be lower than this difficulty
        whole_hash = b""

        # keep making a new hash until it meets the difficulty requirement
        while True:
            whole_hash = self._hash(
                b"\x01\x00\x00\x00",
                self.prev_block_hash,
                self.merkle_root,
                self.timestamp.to_bytes(4, byteorder="little"),
                # will raise `OverflowError` if `nonce` grows larger than 4 bytes
                self.nonce.to_bytes(4, byteorder="little"),
            )
            # hash according to the order of the fields
            # if int.to_bytes(whole_hash, byteorder="little") > int.to_bytes(
            #     temp_difficulty, byteorder="big"
            # ):
            #     # if hash is numerically lower than the difficulty index, this hash has enough zeroes to go through the proof of work
            #     break
            if leading_0_bits(whole_hash) >= self.difficulty:
                return whole_hash
            self.nonce += 1


class BlockSHA256(Block):
    """A block of transitions which hashes using SHA-256"""


class BlockSHA512(Block):
    """A block of transitions which hashes using SHA-512"""

    hash_algorithm = hashlib.sha512
