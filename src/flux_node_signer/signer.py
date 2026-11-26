"""What a delegate's tool does for the nodes it is named for.

An owner names a key for an outpoint as a delegate: a manager key, which may set the
node's keys, or a restart key, which may only start the node with the keys it has.
This module makes the link by which a manager asks to be named, reports from the chain
where each outpoint stands, binds a node's keys from the node's link, and starts a
node that has left the list. It reaches no node: a link is handed to it.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, replace
from enum import StrEnum

from .chain import Chain, NodeState
from .crypto import privkey_to_pubkey, verify_bare
from .exceptions import ValidationError
from .identity import (
    LABEL_PROOF,
    Basis,
    ManagerLink,
    NodeLink,
    Outpoint,
    Role,
    StartV7,
    fingerprint,
    identity_digest,
    key_set_hash,
    txid,
)


class Standing(StrEnum):
    """Where an outpoint stands for a manager."""

    #: The manager key is not a delegate of the outpoint with the manager role.
    NOT_NAMED = "not-named"
    #: Named, and the outpoint has never had an identity key.
    UNBOUND = "unbound"
    #: A start has set keys that the node's machine has not confirmed with yet.
    PENDING = "pending"
    #: An identity key is in force.
    BOUND = "bound"


@dataclass(frozen=True)
class Collateral:
    """What a start names for the collateral: its public key, or for a multisig
    collateral its redeem script."""

    pubkey: bytes | None = None
    redeem_script: bytes | None = None

    def __post_init__(self) -> None:
        if (self.pubkey is None) == (self.redeem_script is None):
            raise ValidationError(
                "a collateral is its public key or its redeem script, one of them"
            )


@dataclass(frozen=True)
class View:
    outpoint: str
    standing: Standing
    role: str | None
    listed: bool
    address: str | None
    identity_key: str | None
    identity_fingerprint: str | None
    in_force_since: int
    pending_identity_key: str | None
    pending_since: int

    def json(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Binding:
    """What bind did for one link. `txid` is the start's id once it is built;
    `sent` says the network was given it."""

    outpoint: str
    identity_fingerprint: str
    outcome: str
    basis: str | None = None
    sign_height: int | None = None
    txid: str | None = None
    transaction: str | None = None
    sent: bool = False

    def json(self) -> dict:
        return asdict(self)


def manager_link(manager_privkey: bytes, outpoints: list[Outpoint]) -> ManagerLink:
    """The link a manager gives one owner: the manager key and that owner's
    outpoints."""
    return ManagerLink.make(manager_privkey, outpoints)


def standing(state: NodeState, manager_key: bytes) -> Standing:
    if state.role_of(manager_key) != Role.MANAGER:
        return Standing.NOT_NAMED
    if state.pending_identity_key is not None:
        return Standing.PENDING
    if state.identity_key is not None:
        return Standing.BOUND
    return Standing.UNBOUND


async def view(
    chain: Chain, manager_key: bytes, outpoints: list[Outpoint]
) -> list[View]:
    """Where each outpoint stands for the manager key, read from the chain."""
    views = []
    for outpoint in outpoints:
        state = await chain.node_state(outpoint)
        role = state.role_of(manager_key)
        views.append(
            View(
                outpoint=str(outpoint),
                standing=standing(state, manager_key),
                role=role.name.lower() if role is not None else None,
                listed=state.listed,
                address=state.address,
                identity_key=state.identity_key.hex() if state.identity_key else None,
                identity_fingerprint=fingerprint(state.identity_key)
                if state.identity_key
                else None,
                in_force_since=state.in_force_since,
                pending_identity_key=(
                    state.pending_identity_key.hex()
                    if state.pending_identity_key
                    else None
                ),
                pending_since=state.pending_since,
            )
        )
    return views


def choose_basis(link: NodeLink, state: NodeState) -> Basis:
    """The basis a start that sets the link's keys states. The chain refuses a false
    one.

    New: the outpoint is not listed and has never had an identity key. Vouched: the
    link's vouch is by the key the chain shows for the node, its identity key in force
    or otherwise a listed node's node key. Replaces: anything else, which is another
    machine taking the node over.
    """
    if state.identity_key is not None:
        return Basis.VOUCHED if link.vouched_by(state.identity_key) else Basis.REPLACES
    if state.listed:
        vouched = state.node_key is not None and link.vouched_by(state.node_key)
        return Basis.VOUCHED if vouched else Basis.REPLACES
    return Basis.NEW


async def bind(
    chain: Chain,
    manager_privkey: bytes,
    link: NodeLink,
    collateral: Collateral,
    *,
    send: bool = True,
    allow_replace: bool = False,
    now: int | None = None,
) -> Binding:
    """Bind the link's keys to its outpoint with a start the manager key signs.

    Nothing is signed for a link whose proof fails, for an outpoint the manager key is
    not named for, or for keys the chain already has in force or pending. A start that
    would replace the machine running a node is built only with `allow_replace`.
    """
    base = Binding(
        outpoint=str(link.outpoint), identity_fingerprint=link.fingerprint(), outcome=""
    )
    if not link.proof_verifies():
        return replace(base, outcome="refused: the link's proof does not verify")
    manager_key = privkey_to_pubkey(manager_privkey, compressed=True)
    state = await chain.node_state(link.outpoint)
    if state.role_of(manager_key) != Role.MANAGER:
        return replace(
            base, outcome="refused: the manager key is not named for this outpoint"
        )
    if state.identity_key == link.identity_key:
        return replace(
            base,
            outcome="nothing to do: these keys are in force"
            + ("" if state.listed else "; restart starts the node with them"),
        )
    if state.pending_identity_key == link.identity_key:
        return replace(
            base, outcome="nothing to do: these keys are pending the node's confirm"
        )

    basis = choose_basis(link, state)
    base = replace(base, basis=basis.name.lower())
    if basis == Basis.REPLACES and not allow_replace:
        where = f" at {state.address}" if state.address else ""
        return replace(
            base,
            outcome=(
                f"refused: this would replace the machine now running the node{where};"
                " the link carries no vouch by the key the chain shows"
            ),
        )
    sign_height = await chain.height()
    transaction = StartV7(
        outpoint=link.outpoint,
        node_key=link.node_key,
        sign_height=sign_height,
        sig_time=int(time.time()) if now is None else now,
        collateral_pubkey=collateral.pubkey,
        redeem_script=collateral.redeem_script,
        link=link,
        basis=basis,
        by_delegate=True,
    ).sign(manager_privkey)
    return await _built(chain, base, sign_height, transaction, send)


async def _built(
    chain: Chain, base: Binding, sign_height: int, transaction: bytes, send: bool
) -> Binding:
    built = replace(
        base,
        sign_height=sign_height,
        txid=txid(transaction),
        transaction=transaction.hex(),
    )
    if not send:
        return replace(built, outcome="built")
    sent_txid = await chain.send(transaction)
    if sent_txid != built.txid:
        return replace(
            built, outcome=f"sent, but the network named it {sent_txid}", sent=True
        )
    return replace(built, outcome="sent", sent=True)


async def restart(
    chain: Chain,
    delegate_privkey: bytes,
    outpoint: Outpoint,
    node_key: bytes,
    collateral: Collateral,
    *,
    send: bool = True,
    now: int | None = None,
) -> Binding:
    """Start a node that is off the list, with the keys it has, by a start a delegate
    of the outpoint signs: a restart key or a manager key.

    With an identity key in force the start carries the keys in force and the proof
    on record, and `node_key` is the node key that proof covers. An outpoint that has
    never had an identity key is started with `node_key` and no keys, which the chain
    takes until it requires every start to carry them.
    """
    state = await chain.node_state(outpoint)
    held = state.identity_key
    base = Binding(
        outpoint=str(outpoint),
        identity_fingerprint=fingerprint(held) if held else "",
        outcome="",
    )
    if state.role_of(privkey_to_pubkey(delegate_privkey, compressed=True)) is None:
        return replace(base, outcome="refused: the key is no delegate of this outpoint")
    if state.listed:
        return replace(base, outcome="nothing to do: the node is on the list")
    link = None
    if held is not None:
        if state.draw_key is None or state.identity_proof is None:
            return replace(
                base, outcome="refused: the chain gave no proof for the keys in force"
            )
        digest = identity_digest(
            LABEL_PROOF, key_set_hash(outpoint, held, state.draw_key, node_key)
        )
        if not verify_bare(digest, state.identity_proof, held):
            return replace(
                base,
                outcome="refused: that is not the node key of the node's keys in force",
            )
        link = NodeLink(outpoint, held, state.identity_proof, state.draw_key, node_key)
    sign_height = await chain.height()
    transaction = StartV7(
        outpoint=outpoint,
        node_key=node_key,
        sign_height=sign_height,
        sig_time=int(time.time()) if now is None else now,
        collateral_pubkey=collateral.pubkey,
        redeem_script=collateral.redeem_script,
        link=link,
        basis=Basis.IN_FORCE,
        by_delegate=True,
    ).sign(delegate_privkey)
    return await _built(
        chain, replace(base, basis="in-force"), sign_height, transaction, send
    )
