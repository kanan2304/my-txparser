"""Command-line entry point: python -m txparser <hex>   (or pipe hex on stdin)."""

from __future__ import annotations

import argparse
import sys

from .parser import parse_hex
from .script import address_for, classify, disassemble

LINE = "-" * 72


def _locktime_text(lt: int) -> str:
    if lt == 0:
        return "no timelock"
    if lt < 500_000_000:
        return f"block height {lt}"
    return f"unix timestamp {lt}"


def _sequence_text(seq: int) -> str:
    if seq == 0xFFFFFFFF:
        return "final"
    if seq < 0xFFFFFFFE:
        return "RBF signalled (BIP-125)"
    return "non-RBF, locktime enabled"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="txparser", description="Parse a raw Bitcoin transaction.")
    ap.add_argument("hex", nargs="?", help="raw transaction hex (read from stdin if omitted)")
    ap.add_argument(
        "--network", choices=["mainnet", "testnet", "regtest"], default="regtest",
        help="network used for address encoding (default: regtest)",
    )
    args = ap.parse_args(argv)

    raw = args.hex if args.hex else sys.stdin.read()
    try:
        tx = parse_hex(raw)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(LINE, "TRANSACTION", LINE, sep="\n")
    print(f"  txid          : {tx.txid}")
    print(f"  wtxid         : {tx.wtxid}")
    print(f"  version       : {tx.version}")
    print(f"  segwit        : {tx.is_segwit}" + ("  (marker 0x00, flag 0x01)" if tx.is_segwit else ""))
    print(f"  locktime      : {tx.locktime}  ({_locktime_text(tx.locktime)})")
    print(f"  size          : {tx.size} bytes")
    print(f"  stripped size : {tx.stripped_size} bytes (witness excluded)")
    print(f"  weight        : {tx.weight} WU  (= 3 x {tx.stripped_size} + {tx.size})")
    print(f"  vsize         : {tx.vsize} vbytes")

    print(LINE, f"INPUTS ({len(tx.inputs)})", LINE, sep="\n")
    for i, txin in enumerate(tx.inputs):
        print(f"  [{i}] byte offset {txin.offset}")
        if txin.is_coinbase:
            print("      COINBASE (null outpoint)")
        print(f"      prev txid  : {txin.prev_txid.hex()}")
        print(f"      prev vout  : {txin.prev_vout}")
        print(f"      scriptSig  : {len(txin.script_sig)} bytes  {txin.script_sig.hex()}")
        print(f"      sequence   : 0x{txin.sequence:08x}  ({_sequence_text(txin.sequence)})")
        if tx.is_segwit:
            print(f"      witness    : {len(txin.witness)} item(s)")
            for j, item in enumerate(txin.witness):
                print(f"        [{j}] ({len(item)} B) {item.hex()}")

    print(LINE, f"OUTPUTS ({len(tx.outputs)})", LINE, sep="\n")
    for i, txout in enumerate(tx.outputs):
        stype, payload = classify(txout.script_pubkey)
        addr = address_for(stype, payload, args.network)
        print(f"  [{i}] byte offset {txout.offset}")
        print(f"      value      : {txout.value_btc} BTC  ({txout.value_sat} sat)")
        print(f"      type       : {stype}")
        print(f"      address    : {addr if addr else '(none)'}")
        print(f"      script     : {' '.join(disassemble(txout.script_pubkey))}")

    print(LINE)
    print(f"  sum of outputs: {tx.total_output_sat} sat")
    print("  Fee: not computable from this transaction alone. fee = sum(inputs) - sum(outputs),")
    print("  but input values live in the previous outputs being spent, which are not included.")
    print(LINE)
    return 0


if __name__ == "__main__":
    sys.exit(main())