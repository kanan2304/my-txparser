"""Extra tests: p2sh / p2wsh (not covered by the reference suite) and the
real Part B transaction from my regtest node."""

from txparser import parse_hex
from txparser.script import address_for, classify, disassemble

# My Part B transaction (from `gettransaction`), block 103 on my regtest chain.
PART_B_HEX = (
    "0200000000010143597846e28d4d58e44e232fcf28200c81b77262c0c827ca0f68e24a59e01648"
    "0000000000fdffffff0200ca9a3b0000000016001459e1e543a1ac853e5daed186278170d3601d"
    "fefbf0006bee0000000016001433099904b034413fff19df9e0841163f2229ec3f024730440220"
    "2a989d0d9c7a96bd1450eb278cf5035f1fda99a3eee4704323368438434a488002204895903811"
    "808cf09e823e9722f8a30b8bb133e75f7fcc572a960c172d2b1d4d01210393e1bf88eda86f16c8"
    "f685b2e41e29e489d3b46a6c3da7f48468bbcc9912595a00000000"
)


def test_p2sh_classification_and_addresses() -> None:
    spk = bytes.fromhex("a914" + "22" * 20 + "87")
    stype, payload = classify(spk)
    assert stype == "p2sh"
    assert payload == b"\x22" * 20
    assert disassemble(spk) == ["OP_HASH160", "<" + "22" * 20 + ">", "OP_EQUAL"]
    assert address_for(stype, payload, "mainnet").startswith("3")
    assert address_for(stype, payload, "regtest").startswith("2")


def test_p2wsh_classification_and_bip173_address() -> None:
    program = "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"
    spk = bytes.fromhex("0020" + program)
    stype, payload = classify(spk)
    assert stype == "p2wsh"
    assert len(payload) == 32
    # BIP-173 mainnet P2WSH test vector
    assert address_for(stype, payload, "mainnet") == (
        "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
    )


def test_nonstandard_script() -> None:
    stype, payload = classify(bytes.fromhex("51"))  # just OP_1
    assert stype == "nonstandard"
    assert address_for(stype, payload) is None


def test_part_b_transaction_matches_node() -> None:
    tx = parse_hex(PART_B_HEX)
    assert tx.txid == "82260dec73577c37bfefaa16969e4012988e9833f5586f6b05b01bc8661ecb9a"
    assert tx.wtxid == "f5239e968649efffc971a4e441e16e5c6ba749f28c93d42064ebdd085b8a4047"
    assert tx.is_segwit
    assert tx.inputs[0].offset == 7
    assert tx.inputs[0].sequence == 0xFFFFFFFD
    assert len(tx.inputs[0].witness) == 2
    assert tx.inputs[0].witness[0][-1] == 0x01   # SIGHASH_ALL
    assert len(tx.inputs[0].witness[1]) == 33     # compressed pubkey
    assert (tx.size, tx.stripped_size, tx.weight, tx.vsize) == (222, 113, 561, 141)
    assert [classify(o.script_pubkey)[0] for o in tx.outputs] == ["p2wpkh", "p2wpkh"]
    assert address_for("p2wpkh", classify(tx.outputs[0].script_pubkey)[1], "regtest") == (
        "bcrt1qt8s72sap4jznuhdw6xrz0qts6dspmlhmyrfu9e"
    )