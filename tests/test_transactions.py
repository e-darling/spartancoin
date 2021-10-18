"""
Unittest coins
"""

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from spartancoin.transactions import Tx, encode_varint


@pytest.fixture(name="private_key")
def fixture_private_key() -> ec.EllipticCurvePrivateKey:
    """Return a repeatable private key"""
    pem = (
        b"-----BEGIN PRIVATE KEY-----\n"
        b"MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgzzPf0DmqcJvV7ff1IGM/\n"
        b"I5mNhcIGLn/LzSGJAkGsuCmhRANCAATPPY+kDUU0A/SyeNILrntRpyD8VjhYAWy6\n"
        b"waA69eghC2WrWbaNchd8RwFNK2k4U4Sx1NfF+ndgWngPdYAXWtWu\n"
        b"-----END PRIVATE KEY-----\n"
    )
    return serialization.load_pem_private_key(pem, None)


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


class TestTx:

    @staticmethod
    def test_genesis(private_key) -> None:
        """Test the Tx class"""
        coinbase = b"Genesis"
        prev_tx_hash = bytearray(32)
        prev_tx_hash[: len(coinbase)] = coinbase

        observed = Tx(prev_tx_hash, -1, private_key).encode()

        assert observed[:32] == prev_tx_hash
        assert observed[32:36] == b'\xFF\xFF\xFF\xFF'

    @staticmethod
    def test_generic(private_key) -> None:
        """Test the Tx class"""
        tmp = b"not genesis"
        prev_tx_hash = bytearray(32)
        prev_tx_hash[: len(tmp)] = tmp

        observed = Tx(prev_tx_hash, 1, private_key).encode()

        assert observed[:32] == prev_tx_hash
        assert observed[32:36] == b'\x01\x00\x00\x00'
