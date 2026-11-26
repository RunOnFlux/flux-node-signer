"""The manager's commands, run as a user runs them."""

import hashlib
import json
from pathlib import Path

import base58
from typer.testing import CliRunner

from flux_node_signer.__main__ import app
from flux_node_signer.crypto import SECP256K1_ORDER

OUTPOINT = "3a27e50730bbcd1b69caa14a80e829be896aa981d35ca625266a59012dbc2d05:0"
MANAGER_LINK = (
    "FLUXMGR1 021dac4faf38d9110dcd52e5434ca4b1f47276df744f3ae3753c945a616423bd2b "
    "9820fa3b86c327d344b77a35550f368ef0c6d591f868f4741cce858f08a839394d331e5706812d01"
    "c1ee522630596ba5facea28be415c4956f7e5ecd51aee0cc "
    "3a27e50730bbcd1b69caa14a80e829be896aa981d35ca625266a59012dbc2d05:0"
)


def key_file(directory: Path, seed: str) -> Path:
    """An unencrypted key file holding the key of the specification's seed."""
    number = int.from_bytes(hashlib.sha256(seed.encode()).digest(), "big")
    secret = (number % (SECP256K1_ORDER - 1) + 1).to_bytes(32, "big")
    path = directory / "manager.key"
    path.write_text(base58.b58encode_check(b"\x80" + secret + b"\x01").decode())
    return path


def test_manager_link_prints_the_link_as_one_json_document(tmp_path: Path) -> None:
    key = key_file(tmp_path, "wallet-spec manager")
    result = CliRunner().invoke(app, ["manager-link", OUTPOINT, "--key-file", str(key)])
    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    assert document["line"] == MANAGER_LINK
    assert document["fingerprint"] == "0a2e 0718 47fb b0e6 32c5 afa1 617f 273e"
    assert document["outpoints"] == [OUTPOINT]


def test_a_bad_outpoint_is_an_error_and_prints_no_document(tmp_path: Path) -> None:
    key = key_file(tmp_path, "wallet-spec manager")
    result = CliRunner().invoke(
        app, ["manager-link", "nonsense", "--key-file", str(key)]
    )
    assert result.exit_code == 1 and result.stdout == ""
    assert "not an outpoint" in result.stderr


def test_view_wants_the_manager_key_one_way() -> None:
    result = CliRunner().invoke(app, ["view", OUTPOINT])
    assert result.exit_code == 1 and "one of them" in result.stderr
