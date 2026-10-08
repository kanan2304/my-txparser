"""Script disassembly, output classification and address encoding."""

from __future__ import annotations

from .parser import hash160, sha256d

# --------------------------------------------------------------------------- #
# Opcodes
# --------------------------------------------------------------------------- #

OPCODES: dict[int, str] = {
    0x00: "OP_0",
    0x4C: "OP_PUSHDATA1",
    0x4D: "OP_PUSHDATA2",
    0x4E: "OP_PUSHDATA4",
    0x4F: "OP_1NEGATE",
    0x50: "OP_RESERVED",
    0x61: "OP_NOP",
    0x63: "OP_IF",
    0x64: "OP_NOTIF",
    0x67: "OP_ELSE",
    0x68: "OP_ENDIF",
    0x69: "OP_VERIFY",
    0x6A: "OP_RETURN",
    0x75: "OP_DROP",
    0x76: "OP_DUP",
    0x7C: "OP_SWAP",
    0x82: "OP_SIZE",
    0x87: "OP_EQUAL",
    0x88: "OP_EQUALVERIFY",
    0xA6: "OP_RIPEMD160",
    0xA7: "OP_SHA1",
    0xA8: "OP_SHA256",
    0xA9: "OP_HASH160",
    0xAA: "OP_HASH256",
    0xAB: "OP_CODESEPARATOR",
    0xAC: "OP_CHECKSIG",
    0xAD: "OP_CHECKSIGVERIFY",
    0xAE: "OP_CHECKMULTISIG",
    0xAF: "OP_CHECKMULTISIGVERIFY",
    0xB1: "OP_CHECKLOCKTIMEVERIFY",
    0xB2: "OP_CHECKSEQUENCEVERIFY",
    0xBA: "OP_CHECKSIGADD",
}
for _n in range(1, 17):  # OP_1 .. OP_16 are 0x51 .. 0x60
    OPCODES[0x50 + _n] = f"OP_{_n}"


def disassemble(script: bytes) -> list[str]:
    """Turn script bytes into a list of opcode mnemonics and <hex> data pushes."""
    ops: list[str] = []
    i, n = 0, len(script)
    while i < n:
        op = script[i]
        i += 1
        if 0x01 <= op <= 0x4B:          # direct push of `op` bytes
            size = op
        elif op in (0x4C, 0x4D, 0x4E):  # PUSHDATA1/2/4: length follows
            width = {0x4C: 1, 0x4D: 2, 0x4E: 4}[op]
            if i + width > n:
                ops.append("[error: truncated PUSHDATA length]")
                break
            size = int.from_bytes(script[i : i + width], "little")
            i += width
        else:                           # a plain opcode
            ops.append(OPCODES.get(op, f"OP_UNKNOWN_0x{op:02x}"))
            continue
        if i + size > n:
            ops.append(f"[error: push of {size} bytes runs past end of script]")
            break
        ops.append("<" + script[i : i + size].hex() + ">")
        i += size
    return ops


# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #

def classify(script: bytes) -> tuple[str, bytes | None]:
    """Return (type, payload) for a scriptPubKey.

    payload is the key, key hash, script hash or witness program -- whatever
    the address is built from. For nulldata it is the data after OP_RETURN.
    """
    s, n = script, len(script)

    # P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    if n == 25 and s[:3] == b"\x76\xa9\x14" and s[23:] == b"\x88\xac":
        return "p2pkh", s[3:23]
    # P2SH: OP_HASH160 <20> OP_EQUAL
    if n == 23 and s[:2] == b"\xa9\x14" and s[22] == 0x87:
        return "p2sh", s[2:22]
    # P2WPKH: OP_0 <20>
    if n == 22 and s[:2] == b"\x00\x14":
        return "p2wpkh", s[2:]
    # P2WSH: OP_0 <32>
    if n == 34 and s[:2] == b"\x00\x20":
        return "p2wsh", s[2:]
    # P2TR: OP_1 <32>
    if n == 34 and s[:2] == b"\x51\x20":
        return "p2tr", s[2:]
    # P2PK: <65-byte uncompressed key> OP_CHECKSIG  or  <33-byte compressed> OP_CHECKSIG
    if n == 67 and s[0] == 0x41 and s[-1] == 0xAC:
        return "p2pk", s[1:66]
    if n == 35 and s[0] == 0x21 and s[-1] == 0xAC:
        return "p2pk", s[1:34]
    # Null data: OP_RETURN ... (provably unspendable, never enters the UTXO set)
    if n >= 1 and s[0] == 0x6A:
        return "nulldata", s[1:]
    return "nonstandard", None


# --------------------------------------------------------------------------- #
# Address encoding
# --------------------------------------------------------------------------- #

NETWORKS = {
    #            P2PKH  P2SH   bech32 prefix
    "mainnet": (0x00, 0x05, "bc"),
    "testnet": (0x6F, 0xC4, "tb"),
    "regtest": (0x6F, 0xC4, "bcrt"),
}

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58check(payload: bytes) -> str:
    data = payload + sha256d(payload)[:4]  # 4-byte checksum
    num = int.from_bytes(data, "big")
    out = ""
    while num:
        num, rem = divmod(num, 58)
        out = _B58[rem] + out
    leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    return "1" * leading_zeros + out


_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_CONST = 1            # BIP-173, witness v0
_BECH32M_CONST = 0x2BC830A3  # BIP-350, witness v1+ (Taproot)


def _polymod(values: list[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= gen[i]
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data: bytes, frombits: int, tobits: int) -> list[int]:
    acc = bits = 0
    out: list[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if bits:
        out.append((acc << (tobits - bits)) & maxv)
    return out


def bech32_encode(hrp: str, witver: int, program: bytes) -> str:
    """Encode a SegWit address. v0 uses Bech32, v1+ uses Bech32m."""
    const = _BECH32_CONST if witver == 0 else _BECH32M_CONST
    data = [witver] + _convertbits(program, 8, 5)
    poly = _polymod(_hrp_expand(hrp) + data + [0] * 6) ^ const
    checksum = [(poly >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CHARSET[d] for d in data + checksum)


def address_for(stype: str, payload: bytes | None, network: str = "mainnet") -> str | None:
    """Return the address for a classified output, or None if it has none."""
    if payload is None or network not in NETWORKS:
        return None
    p2pkh_ver, p2sh_ver, hrp = NETWORKS[network]
    if stype == "p2pk":     # no native address; shown as the P2PKH of its key
        return base58check(bytes([p2pkh_ver]) + hash160(payload))
    if stype == "p2pkh":
        return base58check(bytes([p2pkh_ver]) + payload)
    if stype == "p2sh":
        return base58check(bytes([p2sh_ver]) + payload)
    if stype in ("p2wpkh", "p2wsh"):
        return bech32_encode(hrp, 0, payload)
    if stype == "p2tr":
        return bech32_encode(hrp, 1, payload)
    return None  # nulldata, nonstandard