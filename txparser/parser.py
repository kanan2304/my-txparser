"""Parser for raw Bitcoin transactions (legacy and SegWit)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .reader import Reader, write_compact_size
from .ripemd160 import ripemd160 as _ripemd160_pure


# --------------------------------------------------------------------------- #
# Hash helpers
# --------------------------------------------------------------------------- #

def sha256d(data: bytes) -> bytes:
    """Bitcoin's double SHA-256."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def hash160(data: bytes) -> bytes:
    """RIPEMD160(SHA256(data)) -- used for P2PKH / P2WPKH key hashes."""
    sha = hashlib.sha256(data).digest()
    try:
        return hashlib.new("ripemd160", sha).digest()
    except ValueError:  # OpenSSL build without RIPEMD-160
        return _ripemd160_pure(sha)


# --------------------------------------------------------------------------- #
# Data structures
# --------------------------------------------------------------------------- #

@dataclass
class TxIn:
    prev_txid: bytes          # stored in DISPLAY order (big-endian), as RPC shows it
    prev_vout: int
    script_sig: bytes
    sequence: int
    offset: int               # byte offset where this input starts
    witness: list[bytes] = field(default_factory=list)

    @property
    def is_coinbase(self) -> bool:
        """A coinbase input spends the 'null outpoint': all-zero txid, vout 0xffffffff."""
        return self.prev_txid == b"\x00" * 32 and self.prev_vout == 0xFFFFFFFF


@dataclass
class TxOut:
    value_sat: int
    script_pubkey: bytes
    offset: int

    @property
    def value_btc(self) -> str:
        """Exact decimal string -- never use floats for money."""
        return f"{self.value_sat // 100_000_000}.{self.value_sat % 100_000_000:08d}"


@dataclass
class Transaction:
    version: int
    is_segwit: bool
    inputs: list[TxIn]
    outputs: list[TxOut]
    locktime: int

    def serialise(self, include_witness: bool = True) -> bytes:
        """Rebuild the raw bytes from the parsed fields.

        include_witness=False gives the *legacy* serialisation (no marker, flag
        or witness) -- this is what the txid is computed over.
        """
        with_witness = include_witness and self.is_segwit
        out = bytearray(self.version.to_bytes(4, "little"))
        if with_witness:
            out += b"\x00\x01"  # marker + flag
        out += write_compact_size(len(self.inputs))
        for txin in self.inputs:
            out += txin.prev_txid[::-1]  # back to little-endian (wire order)
            out += txin.prev_vout.to_bytes(4, "little")
            out += write_compact_size(len(txin.script_sig)) + txin.script_sig
            out += txin.sequence.to_bytes(4, "little")
        out += write_compact_size(len(self.outputs))
        for txout in self.outputs:
            out += txout.value_sat.to_bytes(8, "little")
            out += write_compact_size(len(txout.script_pubkey)) + txout.script_pubkey
        if with_witness:
            for txin in self.inputs:
                out += write_compact_size(len(txin.witness))
                for item in txin.witness:
                    out += write_compact_size(len(item)) + item
        out += self.locktime.to_bytes(4, "little")
        return bytes(out)

    # --- identifiers -------------------------------------------------------
    @property
    def txid(self) -> str:
        """Hash of the legacy serialisation, byte-reversed for display."""
        return sha256d(self.serialise(include_witness=False))[::-1].hex()

    @property
    def wtxid(self) -> str:
        """Hash of the full serialisation including witness (BIP-141)."""
        return sha256d(self.serialise(include_witness=True))[::-1].hex()

    # --- sizes (BIP-141) ---------------------------------------------------
    @property
    def size(self) -> int:
        return len(self.serialise(include_witness=True))

    @property
    def stripped_size(self) -> int:
        return len(self.serialise(include_witness=False))

    @property
    def weight(self) -> int:
        return self.stripped_size * 3 + self.size

    @property
    def vsize(self) -> int:
        return (self.weight + 3) // 4

    @property
    def total_output_sat(self) -> int:
        return sum(o.value_sat for o in self.outputs)


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #

def parse_bytes(data: bytes) -> Transaction:
    r = Reader(data)

    version = r.u32()

    # SegWit: after the version comes marker 0x00 and flag 0x01. A legacy tx
    # can never have 0 inputs, so a 0x00 here is unambiguous.
    is_segwit = False
    if r.remaining() >= 2 and data[r.pos] == 0x00 and data[r.pos + 1] == 0x01:
        r.read(2)
        is_segwit = True

    inputs: list[TxIn] = []
    for _ in range(r.compact_size()):
        offset = r.pos
        prev_txid = r.read(32)[::-1]  # wire is little-endian -> reverse for display
        prev_vout = r.u32()
        script_sig = r.read(r.compact_size())
        sequence = r.u32()
        inputs.append(TxIn(prev_txid, prev_vout, script_sig, sequence, offset))

    outputs: list[TxOut] = []
    for _ in range(r.compact_size()):
        offset = r.pos
        value = r.u64()
        script_pubkey = r.read(r.compact_size())
        outputs.append(TxOut(value, script_pubkey, offset))

    # Witness data: one stack per input, in input order.
    if is_segwit:
        for txin in inputs:
            n_items = r.compact_size()
            txin.witness = [r.read(r.compact_size()) for _ in range(n_items)]

    locktime = r.u32()

    if r.remaining():
        raise ValueError(f"{r.remaining()} trailing bytes after locktime")

    return Transaction(version, is_segwit, inputs, outputs, locktime)


def parse_hex(hex_str: str) -> Transaction:
    try:
        data = bytes.fromhex(hex_str.strip())
    except ValueError:
        raise ValueError("input is not valid hexadecimal") from None
    return parse_bytes(data)