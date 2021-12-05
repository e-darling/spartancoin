"""
Unittest blocks
"""

from __future__ import annotations

import pytest

from spartancoin.blocks import Block as _Block
from spartancoin.blocks import BlockSHA256, BlockSHA512
from spartancoin.transactions import Transaction


def test_one(tran: Transaction) -> None:
    """Test can create a block"""
    BlockSHA256(b"qwertyui", [tran])
    BlockSHA512(b"qwertyui", [tran])


@pytest.mark.parametrize("Block", [BlockSHA256, BlockSHA512])
def test_can_hash(Block: type[_Block], tran: Transaction) -> None:
    """Test can hash a block"""
    for difficulty in range(8):
        block = Block(b"qwertyui", [tran], difficulty=difficulty)
        h = block.hash()
        assert h[0] < 2 ** (8 - difficulty)
    for difficulty in range(8, 16):
        block = Block(b"qwertyui", [tran], difficulty=difficulty)
        h = block.hash()
        assert h[0] == 0
        assert h[1] < 2 ** (16 - difficulty)
