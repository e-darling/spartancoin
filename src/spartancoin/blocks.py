from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from typing import cast, Collection, Sequence

import spartancoin.transactions as spartan_transactions

import hashlib
import time
import random

# TODO: Create a static genesis block


def hash_args(*args: Sequence[bytes]):
    """
    Function to hash an entire list of bytes into one hash

    Currently double-hashed SHA-512
    """
    full_bytes = b"0"
    for arg in args:
        full_bytes += arg

    new_hash = hashlib.sha512()
    new_hash.update(full_bytes)
    return_hash = new_hash.digest()
    new_hash2 = hashlib.sha512()
    new_hash2.update(return_hash)
    return_hash = new_hash2.digest()
    return return_hash


def get_difficulty(diff_index: bytes):
    """
    Gets the "number of leading zeroes" from the difficulty index
    Specified by https://en.bitcoin.it/wiki/Difficulty

    Packed Bits Format:
    0x1b0404cb
    <2 bytes exponential position> <6 bytes>

    TODO: Make this work for SHA-512
    """
    intified = int.from_bytes(diff_index, byteorder="little")
    pos = intified >> 24
    lower_24 = intified & 0xFF_FFFF
    limit = lower_24 * 2 ** (8 * (pos - 3))
    return limit.to_bytes(length=32, byteorder="little")


@dataclass
class Block:
    """
    The Block part of the Blockchain

    Information derived from
    https://www.oreilly.com/library/view/mastering-bitcoin/9781491902639/ch07.html

    Block structure:
        Field                                    | Size
        -------------------------------------------------------------------------
        Block size                               | 4 bytes
        Block header                             | 80 bytes
        Transaction counter                      | 1 to 9 bytes VarInt
        Transaction                              | variable

    Block header structure:
    (note: this is the only part that is hashed to identify this block)
        Field                                    | Size
        -------------------------------------------------------------------------
        Version                                  | 4 bytes
        Previous block hash                      | 32 bytes
        Merkle root                              | 32 bytes
        Timestamp                                | 4 bytes
        Difficulty index                         | 4 bytes
        Nonce                                    | 4 bytes
    """

    block_size: int
    # BLOCK HEADER
    version: int
    prev_block_hash: bytes
    merkle_root: bytes
    timestamp: bytes
    difficulty: bytes
    nonce: int
    # END BLOCK HEADER
    transaction_counter: int
    transactions: Sequence[spartan_transactions.Transaction]

    def hash(self) -> bytes:
        """
        Hash the entire block header as proof that these transactions happened
        """
        # generate random nonce
        # get difficulty rating
        # get timestamp
        # get merkle root hash
        # get version
        self.nonce = 0
        """
        self.timestamp = int(time.time())  # epoch time
        self.__hash_merkle__()
        whole_hash = hash_args(
            self.version,
            self.prev_block_hash,
            self.merkle_root,
            self.timestamp,
            self.difficulty,
            self.nonce,
        )
        return whole_hash
        """
        # TODO: loop through the nonce until you get a nonce that is below the difficulty target
        temp_difficulty = get_difficulty(self.difficulty)
        # the generated hash must be lower than this difficulty
        pass

    def __hash_merkle__(self):
        """
        Compute the Merkle Root (binary hash) of every transaction in the block
        using SHA-512
        """
        # Hash every transaction individually first then add them to a list
        hashed_transactions = []
        for tran in self.transactions:
            # hash transaction
            tran_bytes = tran.encode()
            new_hash = hash_args(tran_bytes)
            # add to temporary hashed transaction list
            hashed_transactions.append(new_hash)

        # Combine transactions in pairs, as if we were building a balanced binary tree
        num_transactions = len(hashed_transactions)
        while num_transactions > 1:
            counter = 0
            temp_transactions = []
            while counter < ((num_transactions // 2) * 2):
                pair_hash = hash_args(
                    hashed_transactions[counter], hashed_transactions[counter + 1]
                )
                temp_transactions.append(pair_hash)
                counter += 2
            if num_transactions % 2 == 1 and num_transactions > 1:
                lonely_hash = hash_args(hashed_transactions[counter])
                temp_transactions.append(lonely_hash)
            hashed_transactions = temp_transactions
            num_transactions = len(hashed_transactions)
        # at the end, there should only be one hash
        # assign the last remaining hash to merkle_root
        self.merkle_root = hashed_transactions[0]
