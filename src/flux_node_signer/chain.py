"""What the signer reads from the chain, and how it sends to it.

Nothing a chain answers is trusted for what gets signed: a wrong list gives a start
whose basis the chain refuses, and wrong delegates give a transaction that names a
set the outpoint does not have.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from .exceptions import ValidationError
from .identity import Delegate, Outpoint, Role
from .rpc_client import FluxRPCClient

_ROLES = {"restart": Role.RESTART, "manager": Role.MANAGER}


def _key(value: Any) -> bytes | None:
    return bytes.fromhex(value) if isinstance(value, str) and value else None


@dataclass(frozen=True)
class NodeState:
    """The chain's record of one outpoint."""

    outpoint: Outpoint
    #: On the node list (confirmed).
    listed: bool = False
    #: Where the list says the node answers.
    address: str | None = None
    #: The list's `pubkey`: the node key of the machine running the node.
    node_key: bytes | None = None
    #: The identity key and draw key in force, and the height they have been since.
    identity_key: bytes | None = None
    draw_key: bytes | None = None
    in_force_since: int = 0
    #: A pair a start has set that the node's machine has not confirmed with yet.
    pending_identity_key: bytes | None = None
    pending_since: int = 0
    delegates: list[Delegate] = field(default_factory=list)

    def role_of(self, key: bytes) -> Role | None:
        return next((d.role for d in self.delegates if d.key == key), None)


def node_state(
    outpoint: Outpoint,
    listed: dict[str, Any] | None,
    identity: dict[str, Any],
    delegates: dict[str, Any],
) -> NodeState:
    """Put together fluxd's answers for one outpoint: its row of listfluxnodes (None
    when it is not listed), getidentitykey and listfluxnodedelegates."""
    keys = delegates.get("delegate_keys") or []
    roles = delegates.get("roles") or ["restart"] * len(keys)
    if len(roles) != len(keys) or any(r not in _ROLES for r in roles):
        raise ValidationError(f"the delegates of {outpoint} have no role for every key")
    row = listed or {}
    return NodeState(
        outpoint=outpoint,
        listed=listed is not None,
        address=row.get("ip") or None,
        node_key=_key(row.get("pubkey")),
        identity_key=_key(identity.get("identity_pubkey")),
        draw_key=_key(identity.get("draw_pubkey")),
        in_force_since=int(identity.get("in_force_since") or 0),
        pending_identity_key=_key(row.get("identity_pending_pubkey")),
        pending_since=int(row.get("identity_pending_since") or 0),
        delegates=[
            Delegate(bytes.fromhex(k), _ROLES[r])
            for k, r in zip(keys, roles, strict=True)
        ],
    )


class Chain(Protocol):
    async def height(self) -> int: ...

    async def node_state(self, outpoint: Outpoint) -> NodeState: ...

    async def send(self, transaction: bytes) -> str:
        """Hand a signed transaction to the network; returns its id."""
        ...


class RpcChain:
    """A fluxd reached over its JSON-RPC."""

    def __init__(self, rpc: FluxRPCClient) -> None:
        self.rpc = rpc

    async def height(self) -> int:
        return int(await self.rpc.call("getblockcount"))

    async def node_state(self, outpoint: Outpoint) -> NodeState:
        rows = await self.rpc.call("listfluxnodes", outpoint.txid)
        listed = next(
            (
                row
                for row in rows
                if row.get("txhash") == outpoint.txid
                and int(row.get("outidx", -1)) == outpoint.n
            ),
            None,
        )
        identity = await self.rpc.call("getidentitykey", outpoint.txid, outpoint.n)
        delegates = await self.rpc.call(
            "listfluxnodedelegates", outpoint.txid, str(outpoint.n)
        )
        return node_state(outpoint, listed, identity, delegates)

    async def send(self, transaction: bytes) -> str:
        return await self.rpc.call("sendrawtransaction", transaction.hex())
