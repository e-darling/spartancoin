"""
Unittest utilities
"""

import pytest

from spartancoin.exceptions import DecodeError
from spartancoin.util import decode_varint, encode_varint


class TestVarInt:
    """Test variable-length encoded integers"""

    @staticmethod
    @pytest.mark.parametrize(
        "i, b",
        [
            (0, b"\x00"),
            (252, b"\xFC"),
            (253, b"\xFD\xFD\x00"),
            (255, b"\xFD\xFF\x00"),
            (0x3419, b"\xFD\x19\x34"),
            (0xDC4591, b"\xFE\x91\x45\xDC\x00"),
            (0x80081E5, b"\xFE\xE5\x81\x00\x08"),
            (0xB4DA564E2857, b"\xFFW(NV\xda\xb4\x00\x00"),
            (0x4BF583A17D59C158, b"\xFFX\xc1Y}\xa1\x83\xf5K"),
        ],
    )
    def test_encode_decode(i: int, b: bytes) -> None:
        """
        Test the encoding of variable-length integers.

        Test cases taken from https://wiki.bitcoinsv.io/index.php/VarInt
        """
        assert encode_varint(i) == b
        assert decode_varint(b) == i

    @staticmethod
    @pytest.mark.parametrize("i", [-5, -1, 2 ** 65])
    def test_encode_errors(i: int) -> None:
        """Test variable-length integers are unsigned and can fit in 9 bytes."""
        with pytest.raises(ValueError):
            encode_varint(i)

    @staticmethod
    @pytest.mark.parametrize(
        "b",
        [
            b"",
            b"\xFC-",
            b"\xFD\xFF",
            b"\xFD\x19\x34==",
            b"\xFFW(NV\xda\xb4\x00",
            b"\xFFX\xc1Y}\xa1\x83\xf5K=",
        ],
    )
    def test_decode_errors(b: bytes) -> None:
        """
        Invalid encodings should raise.
        """
        with pytest.raises(DecodeError):
            decode_varint(b)
