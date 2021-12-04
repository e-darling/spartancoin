"""
Unittest blocks
"""

from __future__ import annotations

import random
from timeit import timeit

import pytest

from spartancoin.blocks import Block as _Block
from spartancoin.blocks import BlockSHA256, BlockSHA512
from spartancoin.transactions import Transaction


def rand_block_hash() -> bytes:
    """Return a dummy `Transaction`"""
    return b"".join(bytes([b]) for b in random.choices(b"qwertyuiop", k=64))


def test_one(tran: Transaction) -> None:
    """Test can create a block"""
    BlockSHA256(b"qwertyui", [tran])
    BlockSHA512(b"qwertyui", [tran])


@pytest.mark.parametrize("Block", [BlockSHA256, BlockSHA512])
def test_can_hash(Block: type[_Block], tran: Transaction) -> None:
    """Test can hash a block"""
    block = Block(b"qwertyui", [tran])
    h = block.hash()
    assert h[0] == 0
    assert h[1] == 0


def test_time(tran: Transaction) -> None:
    """Test can hash a block"""
    times = []
    for i in range(10):
        # this `block` variable is used in `timeit`
        print(f"starting {i}")
        block = BlockSHA512(rand_block_hash(), [tran])  # pylint: disable=W0641
        t = timeit("block.hash()", number=1, globals=locals())
        print(f"took {t} seconds")
        times.append(t)
    print(f"average of {sum(t) / len(t)} seconds")
    assert 0
