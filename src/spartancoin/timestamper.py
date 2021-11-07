
from __future__ import annotations

import threading, queue

from dataclasses import dataclass
from io import BytesIO
from typing import cast, Collection, Sequence

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .exceptions import DecodeError

"""
Timestamper

Gives a transaction a timestamp, then hashes its hash to make a new hash
"""
class Timestamper:
    transaction_queue = queue.Queue()

    """
        Add transaction to queue for the server to work on when it gets time
    """
    def enqueue_transaction(self, m_transaction):
        pass

    """
        Private method to actually do the timestamping
    """
    def __timestamp_256__(self, m_transaction):
        """
            Grab the hash from the previous transaction
            Grab an epoch tinestamp
            Hash the two together using SHA-512
            Publish the new hash... somewhere
        """
        pass

    """
        Grab the hashes from the storage
    """
    def get_transaction_hashes(self):
        pass

