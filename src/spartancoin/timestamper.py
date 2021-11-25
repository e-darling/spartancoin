from __future__ import annotations

import threading, queue

from dataclasses import dataclass
from io import BytesIO
from typing import cast, Collection, Sequence

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .exceptions import DecodeError

import time

import spartancoin.transactions as transactions

import hashlib


def MAX_FUTURE_BLOCK_TIME():
    """
    Fake constant that represents 2 hours in seconds to be used with the 2 rules in
    https://en.bitcoin.it/wiki/Block_timestamp

    """
    return 2 * 60 * 60


class Timestamper:
    """
    Performs the necessary hashing calculations to hash a block
    """

    transaction_queue = queue.Queue()

    def enqueue_block(self, m_transaction):
        """
        Add block to queue for the server to work on when it gets time
        """
        #
        pass

    def __timestamp__(self, m_transaction):
        """
        Private method to actually do the timestamping
        """

        # time_bytes = int(time.time()).to_bytes(8, byteorder="little")
        pass
