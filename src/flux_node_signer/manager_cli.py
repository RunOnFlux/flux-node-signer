"""A delegate's commands: each prints one JSON document on standard output.

    manager-link   the link by which a manager asks an owner to name its key
    view           where outpoints stand for a manager key, read from the chain
    bind           bind nodes' keys from their links, signed by the manager key
    restart        start nodes that have left the list, with the keys they have

The chain is a fluxd reached over JSON-RPC, set by FLUX_RPC_HOST, FLUX_RPC_PORT,
FLUX_RPC_USERNAME and FLUX_RPC_PASSWORD or the matching options.
"""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, NoReturn

import typer

from .chain import RpcChain
from .config import settings
from .crypto import decode_wif, privkey_to_pubkey
from .exceptions import FluxDelegateStarterError, ValidationError
from .identity import NodeLink, Outpoint
from .key_manager import DelegateKeyManager
from .rpc_client import FluxRPCClient
from .signer import Collateral, bind, manager_link, restart, view

KEY_FILE = typer.Option(
    ..., "--key-file", "-k", help="The delegate key's file (plain or age-encrypted)"
)
PASSPHRASE = typer.Option(
    None, "--passphrase", "-p", help="The key file's passphrase (asked for when absent)"
)
RPC_HOST = typer.Option(None, "--rpc-host", help="fluxd's RPC host")
RPC_PORT = typer.Option(None, "--rpc-port", help="fluxd's RPC port")
RPC_USER = typer.Option(None, "--rpc-user", help="fluxd's RPC user")
RPC_PASSWORD = typer.Option(None, "--rpc-password", help="fluxd's RPC password")


def _emit(document: Any) -> None:
    json.dump(document, sys.stdout, indent=1)
    sys.stdout.write("\n")


def _fail(message: str) -> NoReturn:
    print(f"error: {message}", file=sys.stderr)
    raise typer.Exit(1)


def _manager_privkey(key_file: Path, passphrase: str | None) -> bytes:
    privkey, _ = decode_wif(DelegateKeyManager.load_key(key_file, passphrase))
    return privkey


def _chain(
    host: str | None, port: int | None, user: str | None, password: str | None
) -> RpcChain:
    return RpcChain(
        FluxRPCClient(
            host=host or settings.rpc_host,
            port=port or settings.rpc_port,
            username=user or settings.rpc_username,
            password=password or settings.rpc_password,
            timeout=settings.rpc_timeout,
        )
    )


def _link(value: Any) -> NodeLink:
    if isinstance(value, str):
        return NodeLink.parse(value)
    if isinstance(value, dict):
        return NodeLink.from_fields(value)
    raise ValidationError("a link is its one line of text or its fields")


def _collateral(entry: dict[str, Any]) -> Collateral:
    pubkey, script = entry.get("collateral_pubkey"), entry.get("redeem_script")
    return Collateral(
        pubkey=bytes.fromhex(pubkey) if pubkey else None,
        redeem_script=bytes.fromhex(script) if script else None,
    )


async def _each(
    entries: list[Any], one: Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]
) -> list[dict[str, Any]]:
    """Run `one` over the entries; one that fails is reported and the rest carry
    on."""
    results: list[dict[str, Any]] = []
    for number, entry in enumerate(entries):
        try:
            results.append(await one(entry))
        except (FluxDelegateStarterError, ValueError, AttributeError) as e:
            results.append({"entry": number, "outcome": f"refused: {e}"})
    return results


def _report(results: list[dict[str, Any]]) -> None:
    """Print the results; exit 2 when any entry was refused."""
    _emit(results)
    done = ("sent", "built", "nothing")
    if any(not r.get("outcome", "").startswith(done) for r in results):
        raise typer.Exit(2)


def register(app: typer.Typer) -> None:
    @app.command("manager-link")
    def manager_link_command(
        outpoints: list[str] = typer.Argument(
            ..., help="One owner's outpoints, each txid:n"
        ),
        key_file: Path = KEY_FILE,
        passphrase: str | None = PASSPHRASE,
    ) -> None:
        """The manager link for one owner's outpoints, as one line and by field."""
        try:
            link = manager_link(
                _manager_privkey(key_file, passphrase),
                [Outpoint.parse(o) for o in outpoints],
            )
        except (FluxDelegateStarterError, ValueError) as e:
            _fail(str(e))
        _emit({"line": link.line(), **link.fields()})

    @app.command("view")
    def view_command(
        outpoints: list[str] = typer.Argument(..., help="Outpoints, each txid:n"),
        manager_key: str | None = typer.Option(
            None, "--manager-key", help="The manager's public key, 66 hex"
        ),
        key_file: Path | None = typer.Option(
            None, "--key-file", "-k", help="The manager key's file, in its place"
        ),
        passphrase: str | None = PASSPHRASE,
        rpc_host: str | None = RPC_HOST,
        rpc_port: int | None = RPC_PORT,
        rpc_user: str | None = RPC_USER,
        rpc_password: str | None = RPC_PASSWORD,
    ) -> None:
        """Where each outpoint stands for the manager key: not named, unbound,
        pending or bound."""
        try:
            if (manager_key is None) == (key_file is None):
                raise ValidationError("give --manager-key or --key-file, one of them")
            if key_file is not None:
                public = privkey_to_pubkey(
                    _manager_privkey(key_file, passphrase), compressed=True
                )
            else:
                public = bytes.fromhex(manager_key or "")
            chain = _chain(rpc_host, rpc_port, rpc_user, rpc_password)
            views = asyncio.run(
                view(chain, public, [Outpoint.parse(o) for o in outpoints])
            )
        except (FluxDelegateStarterError, ValueError) as e:
            _fail(str(e))
        _emit([v.json() for v in views])

    @app.command("bind")
    def bind_command(
        input_file: Path = typer.Argument(
            ...,
            help=(
                "A JSON list; each entry has a node's link (its line or its fields)"
                " under 'link' and 'collateral_pubkey' or 'redeem_script'"
            ),
        ),
        key_file: Path = KEY_FILE,
        passphrase: str | None = PASSPHRASE,
        dry_run: bool = typer.Option(
            False, "--dry-run", help="Build and sign, send nothing"
        ),
        allow_replace: bool = typer.Option(
            False,
            "--allow-replace",
            help="Bind a link that replaces the machine now running a node",
        ),
        rpc_host: str | None = RPC_HOST,
        rpc_port: int | None = RPC_PORT,
        rpc_user: str | None = RPC_USER,
        rpc_password: str | None = RPC_PASSWORD,
    ) -> None:
        """Bind each node's keys with a start the manager key signs. An entry that
        cannot be bound is reported and the rest carry on."""
        try:
            entries = json.loads(input_file.read_text())
            if not isinstance(entries, list):
                raise ValidationError("the input is a JSON list")
            privkey = _manager_privkey(key_file, passphrase)
            chain = _chain(rpc_host, rpc_port, rpc_user, rpc_password)
        except (FluxDelegateStarterError, ValueError, OSError) as e:
            _fail(str(e))

        async def one(entry: dict[str, Any]) -> dict[str, Any]:
            done = await bind(
                chain,
                privkey,
                _link(entry.get("link")),
                _collateral(entry),
                send=not dry_run,
                allow_replace=allow_replace,
            )
            return done.json()

        _report(asyncio.run(_each(entries, one)))

    @app.command("restart")
    def restart_command(
        input_file: Path = typer.Argument(
            ...,
            help=(
                "A JSON list; each entry has 'outpoint' (txid:n), 'node_key' (hex),"
                " and 'collateral_pubkey' or 'redeem_script'"
            ),
        ),
        key_file: Path = KEY_FILE,
        passphrase: str | None = PASSPHRASE,
        dry_run: bool = typer.Option(
            False, "--dry-run", help="Build and sign, send nothing"
        ),
        rpc_host: str | None = RPC_HOST,
        rpc_port: int | None = RPC_PORT,
        rpc_user: str | None = RPC_USER,
        rpc_password: str | None = RPC_PASSWORD,
    ) -> None:
        """Start each node that has left the list, with the keys it has, by a start a
        restart key or a manager key signs."""
        try:
            entries = json.loads(input_file.read_text())
            if not isinstance(entries, list):
                raise ValidationError("the input is a JSON list")
            privkey = _manager_privkey(key_file, passphrase)
            chain = _chain(rpc_host, rpc_port, rpc_user, rpc_password)
        except (FluxDelegateStarterError, ValueError, OSError) as e:
            _fail(str(e))

        async def one(entry: dict[str, Any]) -> dict[str, Any]:
            done = await restart(
                chain,
                privkey,
                Outpoint.parse(entry.get("outpoint", "")),
                bytes.fromhex(entry.get("node_key", "")),
                _collateral(entry),
                send=not dry_run,
            )
            return done.json()

        _report(asyncio.run(_each(entries, one)))
