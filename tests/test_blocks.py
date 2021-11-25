from pathlib import Path
from typing import cast

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import hashlib

from spartancoin.transactions import (
    decode_varint,
    DecodeError,
    encode_varint,
    Receiver,
    Sender,
    Transaction,
)
from spartancoin.blocks import (
    get_difficulty,
    hash_args,
    Block,
)
