"""
This module contains utility functions.
"""

from io import BytesIO

from .exceptions import DecodeError


def encode_varint(i: int) -> bytes:
    r"""
    Encode a variable-length integer in little endian as per
    https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer

    >>> encode_varint(252)
    b'\xfc'
    >>> encode_varint(255)
    b'\xfd\xff\x00'
    """
    if i < 0:
        raise ValueError(f"invalid: {i!r}")
    if i < 0xFD:
        return i.to_bytes(1, byteorder="little")
    if i <= 0xFFFF:
        return b"\xFD" + i.to_bytes(2, byteorder="little")
    if i <= 0xFFFF_FFFF:
        return b"\xFE" + i.to_bytes(4, byteorder="little")
    if i <= 0xFFFF_FFFF_FFFF_FFFF:
        return b"\xFF" + i.to_bytes(8, byteorder="little")
    raise ValueError(f"invalid: {i!r}")


def assert_read(f: BytesIO, n: int) -> bytes:
    """
    Read and assert length is as expected

    >>> f = BytesIO(b"01")
    >>> assert_read(f, 1)
    b'0'
    >>> assert_read(f, 2)
    Traceback (most recent call last):
      ...
    spartancoin.exceptions.DecodeError: Expecting length 2
    """
    d = f.read(n)
    if len(d) != n:
        raise DecodeError(f"Expecting length {n:d}")
    return d


def decode_varint(b: bytes) -> int:
    r"""
    Decode a variable-length integer in little endian as per
    https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer

    >>> decode_varint(b"\xfc")
    252
    >>> decode_varint(b"\xfd\xff\x00")
    255
    """
    with BytesIO(b) as f:
        n = raw_decode_varint(f)
        if f.read(1):
            # have already parsed the varint, but there are still things after it
            raise DecodeError("Extra data")
    return n


def raw_decode_varint(f: BytesIO) -> int:
    r"""
    Decode (raw) a variable-length integer in little endian as per
    https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer

    >>> b = BytesIO(b"\xfc\xff")
    >>> raw_decode_varint(b)
    252
    >>> b.read()
    b'\xff'
    """
    sentinel = assert_read(f, 1)
    if sentinel < b"\xFD":
        return int.from_bytes(sentinel, byteorder="little")
    if sentinel == b"\xFD":
        d = assert_read(f, 2)
    elif sentinel == b"\xFE":
        d = assert_read(f, 4)
    else:  # sentinel == b"\xFF":
        d = assert_read(f, 8)
    return int.from_bytes(d, byteorder="little")
