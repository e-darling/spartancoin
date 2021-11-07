
from __future__ import annotations

from dataclasses import dataclass
from typing import cast, Collection

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .exceptions import DecodeError

import threading, queue

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
    def __timestamp__(self, m_transaction):
        pass

    """
        Grab 
    """
    def get_transaction_hashes(self):
        pass

