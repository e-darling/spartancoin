"""
Unittest coins
"""

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from spartancoin.transactions import encode_varint


@pytest.fixture(name="private_key")
def fixture_private_key() -> ec.EllipticCurvePrivateKey:
    """Return a random private key"""
    return ec.generate_private_key(ec.SECP256K1())


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
def test_encode_varint(i: int, b: bytes) -> None:
    """
    Test the encoding of variable-length integers.

    Test cases taken from https://wiki.bitcoinsv.io/index.php/VarInt
    """
    assert encode_varint(i) == b


@pytest.mark.parametrize("i", [-5, -1, 2 ** 65])
def test_encode_varint_invalid(i: int) -> None:
    """Test variable-length integers are unsigned and can fit in 9 bytes."""
    with pytest.raises(ValueError):
        encode_varint(i)
