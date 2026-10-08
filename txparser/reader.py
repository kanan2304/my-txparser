"""Byte cursor and CompactSize (VarInt) encoding."""

from __future__ import annotations


def read_compact_size(buf: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode a CompactSize at `offset`. Returns (value, bytes_consumed).

    First byte < 0xfd  -> the value itself (1 byte total)
    0xfd               -> next 2 bytes, little-endian (3 bytes total)
    0xfe               -> next 4 bytes, little-endian (5 bytes total)
    0xff               -> next 8 bytes, little-endian (9 bytes total)
    """
    if offset >= len(buf):
        raise ValueError(f"truncated CompactSize at offset {offset}")
    first = buf[offset]
    if first < 0xFD:
        return first, 1
    width = {0xFD: 2, 0xFE: 4, 0xFF: 8}[first]
    end = offset + 1 + width
    if end > len(buf):
        raise ValueError(f"truncated CompactSize at offset {offset}")
    return int.from_bytes(buf[offset + 1 : end], "little"), 1 + width


def write_compact_size(n: int) -> bytes:
    """Encode an integer as a CompactSize using the shortest form."""
    if n < 0:
        raise ValueError("CompactSize cannot be negative")
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    if n <= 0xFFFFFFFFFFFFFFFF:
        return b"\xff" + n.to_bytes(8, "little")
    raise ValueError("CompactSize value too large")


class Reader:
    """Reads a byte string from left to right, tracking the current offset."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def read(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise ValueError(
                f"truncated transaction: needed {n} bytes at offset {self.pos}, "
                f"only {self.remaining()} left"
            )
        chunk = self.data[self.pos : self.pos + n]
        self.pos += n
        return chunk

    def u32(self) -> int:
        return int.from_bytes(self.read(4), "little")

    def u64(self) -> int:
        return int.from_bytes(self.read(8), "little")

    def compact_size(self) -> int:
        value, consumed = read_compact_size(self.data, self.pos)
        self.pos += consumed
        return value