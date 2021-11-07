
from __future__ import annotations

import threading, queue

from dataclasses import dataclass
from io import BytesIO
from typing import cast, Collection, Sequence

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .exceptions import DecodeError

def MAX_FUTURE_BLOCK_TIME():
    """
        Fake constant that represents 2 hours in seconds
        According to https://en.bitcoin.it/wiki/Block_timestamp
        
    """
    return 2*60*60

class Timestamper:
    """
        Gives a transaction a timestamp, then hashes its hash to make a new hash
    """
    transaction_queue = queue.Queue()

    def enqueue_transaction(self, m_transaction):
        """
            Add transaction to queue for the server to work on when it gets time
        """
        # 
        pass

    def __timestamp_512__(self, m_transaction):
        """
            Private method to actually do the timestamping
        """
        # Grab the hash from the previous transaction
        # Grab an epoch timestamp
        # Hash the two together using SHA-512
        # "Broadcast" the hash (fake this by adding it to a singular database)
        # Timestamp has to be greater than the
        #   timestamp from 6 transactions ago 
        pass

    def get_transaction_hashes(self):
        """
            Grab the hashes from the storage
        """
        pass

