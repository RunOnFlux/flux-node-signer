"""The node-identity formats of a version 7 fluxnode transaction.

Everything here is bytes and signatures: a node's link and its checks, a manager
link, the delegates record, and the version 7 start and delegate transactions.
Nothing reads a chain or a file. Integers are little-endian; a txid in text is its
hash's bytes reversed.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from enum import IntEnum

from coincurve import PublicKey

from .crypto import (
    hash256,
    privkey_to_pubkey,
    sha256,
    sign_bare,
    sign_compact,
    verify_bare,
)
from .exceptions import ValidationError

NODE_TX_VERSION = 7
START_TX_TYPE = 2
DELEGATE_TX_TYPE = 18

TYPE_NORMAL_BIT = 0x0001
TYPE_P2SH_BIT = 0x0002
FEATURE_DELEGATES_BIT = 0x0100
FEATURE_IDENTITY_BIT = 0x0200

LABEL_PROOF = b"FLUXPOP1"
LABEL_VOUCH = b"FLUXLNK1"
LABEL_START = b"FLUXSTR1"
LABEL_DELEGATE = b"FLUXDLG1"
LABEL_MANAGER = b"FLUXMGR1"

NODE_LINK_PREFIX = "FLUXID1"
MANAGER_LINK_PREFIX = "FLUXMGR1"

DELEGATES_RECORD_VERSION = 2
DELEGATES_UPDATE = 1
DELEGATES_SIGNING = 2
MAX_DELEGATES = 4

_HEX = re.compile(r"[0-9a-f]*")
_OUTPOINT = re.compile(r"([0-9a-f]{64}):(0|[1-9][0-9]{0,9})")


class Basis(IntEnum):
    """What a start says of the keys it carries. The chain refuses a false one."""

    IN_FORCE = 0
    NEW = 1
    VOUCHED = 2
    REPLACES = 3


class Role(IntEnum):
    """A restart key starts a node with the keys it has; a manager key may also set
    them."""

    RESTART = 0
    MANAGER = 1


def compact_size(n: int) -> bytes:
    if n < 253:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def var_bytes(data: bytes) -> bytes:
    return compact_size(len(data)) + data


def _hex(text: str, length: int, what: str) -> bytes:
    if len(text) != length or not _HEX.fullmatch(text):
        raise ValidationError(f"{what} is not {length} lower-case hex characters")
    return bytes.fromhex(text)


def _point(key: bytes, what: str, *, compressed_only: bool = True) -> bytes:
    """The key, once it is known to be a point on the curve in an accepted form."""
    lengths = (33,) if compressed_only else (33, 65)
    if len(key) not in lengths:
        raise ValidationError(f"{what} is {len(key)} bytes")
    try:
        PublicKey(key)
    except ValueError as e:
        raise ValidationError(f"{what} is not a point on the curve") from e
    return key


@dataclass(frozen=True, order=True)
class Outpoint:
    txid: str
    n: int

    def __post_init__(self) -> None:
        _hex(self.txid, 64, "an outpoint's txid")
        if not 0 <= self.n <= 0xFFFFFFFF:
            raise ValidationError(
                f"an outpoint's output number {self.n} is out of range"
            )

    @classmethod
    def parse(cls, text: str) -> Outpoint:
        match = _OUTPOINT.fullmatch(text)
        if not match or int(match.group(2)) > 0xFFFFFFFF:
            raise ValidationError(f"not an outpoint: {text!r}")
        return cls(match.group(1), int(match.group(2)))

    def serialize(self) -> bytes:
        return bytes.fromhex(self.txid)[::-1] + struct.pack("<I", self.n)

    def __str__(self) -> str:
        return f"{self.txid}:{self.n}"


def identity_digest(label: bytes, hashed: bytes) -> bytes:
    """What an identity signature is over: the use's eight-byte label, then a 32-byte
    hash."""
    if len(label) != 8 or len(hashed) != 32:
        raise ValueError("a label is 8 bytes and a hash 32")
    return hash256(label + hashed)


def key_set_hash(
    outpoint: Outpoint, identity_key: bytes, draw_key: bytes, node_key: bytes
) -> bytes:
    return hash256(outpoint.serialize() + identity_key + draw_key + var_bytes(node_key))


def fingerprint(key: bytes) -> str:
    """The first sixteen bytes of the key's SHA-256, as eight groups of four hex
    characters."""
    digest = sha256(key)[:16].hex()
    return " ".join(digest[i : i + 4] for i in range(0, 32, 4))


@dataclass(frozen=True)
class NodeLink:
    """A node's three public keys for an outpoint, with the proof that its identity
    key is held and, from a machine already running the node, a vouch by the key the
    chain shows."""

    outpoint: Outpoint
    identity_key: bytes
    proof: bytes
    draw_key: bytes
    node_key: bytes
    vouch: bytes | None = None

    def __post_init__(self) -> None:
        _point(self.identity_key, "the identity key")
        _point(self.draw_key, "the draw key")
        _point(self.node_key, "the node key", compressed_only=False)
        if len(self.proof) != 64:
            raise ValidationError("the proof is not 64 bytes")
        if self.vouch is not None and len(self.vouch) != 64:
            raise ValidationError("the vouch is not 64 bytes")

    @classmethod
    def parse(cls, line: str) -> NodeLink:
        """Read the one-line form. Anything but an exact link is refused."""
        parts = line.split(" ")
        if len(parts) not in (6, 7) or parts[0] != NODE_LINK_PREFIX:
            raise ValidationError("not a node's link")
        node_key_hex = parts[5]
        return cls(
            Outpoint.parse(parts[1]),
            _hex(parts[2], 66, "the identity key"),
            _hex(parts[3], 128, "the proof"),
            _hex(parts[4], 66, "the draw key"),
            _hex(node_key_hex, 130 if len(node_key_hex) == 130 else 66, "the node key"),
            _hex(parts[6], 128, "the vouch") if len(parts) == 7 else None,
        )

    @classmethod
    def from_fields(cls, fields: dict[str, str]) -> NodeLink:
        """Read the by-field form, as fluxd's getfluxnodestatus gives it in
        identity_link."""
        allowed = {"outpoint", "identitykey", "proof", "drawkey", "nodekey", "vouch"}
        if not allowed - {"vouch"} <= fields.keys() <= allowed:
            raise ValidationError("not a node's link")
        line = " ".join(
            [NODE_LINK_PREFIX]
            + [
                fields[k]
                for k in ("outpoint", "identitykey", "proof", "drawkey", "nodekey")
            ]
            + ([fields["vouch"]] if "vouch" in fields else [])
        )
        return cls.parse(line)

    def line(self) -> str:
        parts = [
            NODE_LINK_PREFIX,
            str(self.outpoint),
            self.identity_key.hex(),
            self.proof.hex(),
            self.draw_key.hex(),
            self.node_key.hex(),
        ]
        if self.vouch is not None:
            parts.append(self.vouch.hex())
        return " ".join(parts)

    def key_set_hash(self) -> bytes:
        return key_set_hash(
            self.outpoint, self.identity_key, self.draw_key, self.node_key
        )

    def proof_verifies(self) -> bool:
        """Whether the identity key signed this outpoint and these three keys."""
        return verify_bare(
            identity_digest(LABEL_PROOF, self.key_set_hash()),
            self.proof,
            self.identity_key,
        )

    def vouched_by(self, key: bytes) -> bool:
        """Whether the link carries a vouch that `key` signed."""
        return self.vouch is not None and verify_bare(
            identity_digest(LABEL_VOUCH, self.key_set_hash()), self.vouch, key
        )

    def fingerprint(self) -> str:
        return fingerprint(self.identity_key)


def manager_hash(manager_key: bytes, outpoints: list[Outpoint]) -> bytes:
    return hash256(
        manager_key
        + compact_size(len(outpoints))
        + b"".join(o.serialize() for o in outpoints)
    )


@dataclass(frozen=True)
class ManagerLink:
    """A manager key and the outpoints it asks to be named for, signed by that key. An
    owner's wallet reads it; the chain never sees it."""

    manager_key: bytes
    proof: bytes
    outpoints: tuple[Outpoint, ...]

    def __post_init__(self) -> None:
        _point(self.manager_key, "the manager key")
        if len(self.proof) != 64:
            raise ValidationError("the proof is not 64 bytes")
        if not self.outpoints:
            raise ValidationError("a manager link names at least one outpoint")
        if len(set(self.outpoints)) != len(self.outpoints):
            raise ValidationError("a manager link names an outpoint twice")

    @classmethod
    def make(cls, manager_privkey: bytes, outpoints: list[Outpoint]) -> ManagerLink:
        manager_key = privkey_to_pubkey(manager_privkey, compressed=True)
        digest = identity_digest(LABEL_MANAGER, manager_hash(manager_key, outpoints))
        return cls(manager_key, sign_bare(digest, manager_privkey), tuple(outpoints))

    @classmethod
    def parse(cls, line: str) -> ManagerLink:
        parts = line.split(" ")
        if len(parts) < 4 or parts[0] != MANAGER_LINK_PREFIX:
            raise ValidationError("not a manager link")
        return cls(
            _hex(parts[1], 66, "the manager key"),
            _hex(parts[2], 128, "the proof"),
            tuple(Outpoint.parse(p) for p in parts[3:]),
        )

    @classmethod
    def from_fields(cls, fields: dict) -> ManagerLink:
        if fields.keys() - {"fingerprint"} != {"managerkey", "proof", "outpoints"}:
            raise ValidationError("not a manager link")
        return cls.parse(
            " ".join(
                [
                    MANAGER_LINK_PREFIX,
                    fields["managerkey"],
                    fields["proof"],
                    *fields["outpoints"],
                ]
            )
        )

    def line(self) -> str:
        return " ".join(
            [
                MANAGER_LINK_PREFIX,
                self.manager_key.hex(),
                self.proof.hex(),
                *map(str, self.outpoints),
            ]
        )

    def fields(self) -> dict:
        return {
            "managerkey": self.manager_key.hex(),
            "fingerprint": self.fingerprint(),
            "proof": self.proof.hex(),
            "outpoints": [str(o) for o in self.outpoints],
        }

    def proof_verifies(self) -> bool:
        digest = identity_digest(
            LABEL_MANAGER, manager_hash(self.manager_key, list(self.outpoints))
        )
        return verify_bare(digest, self.proof, self.manager_key)

    def fingerprint(self) -> str:
        return fingerprint(self.manager_key)


@dataclass(frozen=True)
class Delegate:
    key: bytes
    role: Role

    def __post_init__(self) -> None:
        _point(self.key, "a delegate key")


def delegates_record(delegates: list[Delegate]) -> bytes:
    """The record that sets an outpoint's whole set of delegates; none removes them
    all."""
    if len(delegates) > MAX_DELEGATES:
        raise ValidationError(f"an outpoint has at most {MAX_DELEGATES} delegates")
    return (
        struct.pack("<bb", DELEGATES_RECORD_VERSION, DELEGATES_UPDATE)
        + compact_size(len(delegates))
        + b"".join(var_bytes(d.key) for d in delegates)
        + var_bytes(bytes(d.role for d in delegates))
    )


def delegates_hash(delegates: list[Delegate]) -> bytes:
    """The hash a transaction names for the set it replaces. An outpoint with no
    delegates is named by 32 zero bytes, not by this hash of an empty set."""
    return hash256(
        compact_size(len(delegates))
        + b"".join(var_bytes(d.key) + bytes([d.role]) for d in delegates)
    )


NO_DELEGATES = bytes(32)


def _collateral_flags(redeem_script: bytes | None) -> int:
    return TYPE_P2SH_BIT if redeem_script is not None else TYPE_NORMAL_BIT


def _signed(unsigned: bytes, label: bytes, privkey: bytes) -> bytes:
    signature = sign_compact(
        identity_digest(label, hash256(unsigned)), privkey, compressed=True
    )
    return unsigned + var_bytes(signature)


def txid(transaction: bytes) -> str:
    """A version 7 transaction's id covers all of it, the signature included."""
    return hash256(transaction)[::-1].hex()


@dataclass(frozen=True)
class StartV7:
    """A version 7 start.

    For an ordinary collateral `collateral_pubkey` is the collateral's key; for a
    multisig one `redeem_script` is its script and `collateral_pubkey` is unused.
    With `link` and a basis other than IN_FORCE the start sets the link's keys.
    `by_delegate` says a delegate of the outpoint signs in the owner's place.
    """

    outpoint: Outpoint
    node_key: bytes
    sign_height: int
    sig_time: int
    collateral_pubkey: bytes | None = None
    redeem_script: bytes | None = None
    link: NodeLink | None = None
    basis: Basis = Basis.IN_FORCE
    by_delegate: bool = False

    def __post_init__(self) -> None:
        if (self.collateral_pubkey is None) == (self.redeem_script is None):
            raise ValidationError(
                "a start names the collateral's key or its redeem script, one of them"
            )
        if (self.link is None) != (self.basis == Basis.IN_FORCE):
            raise ValidationError(
                "a start carries keys exactly when its basis is not the keys in force"
            )
        if self.link is not None:
            if (
                self.link.outpoint != self.outpoint
                or self.link.node_key != self.node_key
            ):
                raise ValidationError("the link is for another outpoint or node key")
            if self.basis == Basis.VOUCHED and self.link.vouch is None:
                raise ValidationError("a vouched start needs the link's vouch")

    def unsigned(self) -> bytes:
        flags = _collateral_flags(self.redeem_script)
        identity = b""
        delegates = b""
        if self.link is not None:
            flags |= FEATURE_IDENTITY_BIT
            identity = (
                self.link.identity_key
                + self.link.proof
                + self.link.draw_key
                + bytes([self.basis])
            )
            if self.basis == Basis.VOUCHED:
                assert self.link.vouch is not None
                identity += self.link.vouch
        if self.by_delegate:
            flags |= FEATURE_DELEGATES_BIT
            # fUsingDelegates, a signing record (it carries no keys), no set replaced.
            delegates = (
                b"\x01"
                + struct.pack("<bb", DELEGATES_RECORD_VERSION, DELEGATES_SIGNING)
                + NO_DELEGATES
            )
        return (
            struct.pack(
                "<IbII", NODE_TX_VERSION, START_TX_TYPE, flags, self.sign_height
            )
            + self.outpoint.serialize()
            + (
                var_bytes(self.collateral_pubkey)
                if self.collateral_pubkey is not None
                else b""
            )
            + var_bytes(self.node_key)
            + (var_bytes(self.redeem_script) if self.redeem_script is not None else b"")
            + struct.pack("<I", self.sig_time)
            + identity
            + delegates
        )

    def sign(self, privkey: bytes) -> bytes:
        return _signed(self.unsigned(), LABEL_START, privkey)


@dataclass(frozen=True)
class DelegateTxV7:
    """A delegate transaction: the collateral's owner sets the outpoint's whole set of
    delegates, naming the set it replaces (NO_DELEGATES when the outpoint has none)."""

    outpoint: Outpoint
    sign_height: int
    sig_time: int
    delegates: list[Delegate] = field(default_factory=list)
    replaces: bytes = NO_DELEGATES
    collateral_pubkey: bytes | None = None
    redeem_script: bytes | None = None

    def __post_init__(self) -> None:
        if (self.collateral_pubkey is None) == (self.redeem_script is None):
            raise ValidationError(
                "a delegate transaction names the collateral's key or its redeem"
                " script, one of them"
            )
        if len(self.replaces) != 32:
            raise ValidationError("the hash of the set replaced is 32 bytes")

    def unsigned(self) -> bytes:
        collateral = (
            self.redeem_script
            if self.redeem_script is not None
            else self.collateral_pubkey
        )
        assert collateral is not None
        return (
            struct.pack(
                "<IbII",
                NODE_TX_VERSION,
                DELEGATE_TX_TYPE,
                _collateral_flags(self.redeem_script),
                self.sign_height,
            )
            + self.outpoint.serialize()
            + var_bytes(collateral)
            + struct.pack("<I", self.sig_time)
            + delegates_record(self.delegates)
            + self.replaces
        )

    def sign(self, privkey: bytes) -> bytes:
        return _signed(self.unsigned(), LABEL_DELEGATE, privkey)
