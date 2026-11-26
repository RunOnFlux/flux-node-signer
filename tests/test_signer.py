"""A manager's bindings, against a chain that answers from a table."""

import hashlib

from flux_node_signer.chain import NodeState, node_state
from flux_node_signer.crypto import SECP256K1_ORDER, privkey_to_pubkey, sign_bare
from flux_node_signer.identity import (
    LABEL_PROOF,
    LABEL_VOUCH,
    Basis,
    Delegate,
    NodeLink,
    Outpoint,
    Role,
    StartV7,
    identity_digest,
    key_set_hash,
)
from flux_node_signer.signer import (
    Collateral,
    Standing,
    bind,
    choose_basis,
    manager_link,
    standing,
    view,
)

NOW = 1795000000
HEIGHT = 450


def secret(seed: str) -> bytes:
    number = int.from_bytes(hashlib.sha256(seed.encode()).digest(), "big")
    return (number % (SECP256K1_ORDER - 1) + 1).to_bytes(32, "big")


def public(seed: str) -> bytes:
    return privkey_to_pubkey(secret(seed), compressed=True)


OUTPOINT = Outpoint(hashlib.sha256(b"signer outpoint").hexdigest(), 3)
MANAGER = secret("signer manager")
COLLATERAL = Collateral(pubkey=public("signer collateral"))
MANAGED = [Delegate(public("signer manager"), Role.MANAGER)]


def link(
    machine: str = "a", vouched_by: str | None = None, outpoint: Outpoint = OUTPOINT
) -> NodeLink:
    """A machine's link: its three keys, its proof, and a vouch by the key named."""
    identity, draw, node = (
        public(f"{machine} {k}") for k in ("identity", "draw", "node")
    )
    key_set = key_set_hash(outpoint, identity, draw, node)
    return NodeLink(
        outpoint,
        identity,
        sign_bare(identity_digest(LABEL_PROOF, key_set), secret(f"{machine} identity")),
        draw,
        node,
        sign_bare(identity_digest(LABEL_VOUCH, key_set), secret(vouched_by))
        if vouched_by
        else None,
    )


class TableChain:
    def __init__(self, *states: NodeState) -> None:
        self.states = {s.outpoint: s for s in states}
        self.sent: list[bytes] = []

    async def height(self) -> int:
        return HEIGHT

    async def node_state(self, outpoint: Outpoint) -> NodeState:
        return self.states.get(outpoint, NodeState(outpoint))

    async def send(self, transaction: bytes) -> str:
        self.sent.append(transaction)
        return hashlib.sha256(hashlib.sha256(transaction).digest()).digest()[::-1].hex()


def test_the_basis_is_what_the_chain_shows_for_the_outpoint() -> None:
    unlisted = NodeState(OUTPOINT)
    listed = NodeState(OUTPOINT, listed=True, node_key=public("a node"))
    bound = NodeState(
        OUTPOINT,
        listed=True,
        node_key=public("a node"),
        identity_key=public("a identity"),
    )
    assert choose_basis(link("a"), unlisted) == Basis.NEW
    assert choose_basis(link("a", vouched_by="a node"), unlisted) == Basis.NEW
    # the first binding of a running node: vouched by the node key the list shows
    assert choose_basis(link("a", vouched_by="a node"), listed) == Basis.VOUCHED
    assert choose_basis(link("b", vouched_by="b node"), listed) == Basis.REPLACES
    assert choose_basis(link("a"), listed) == Basis.REPLACES
    # the same machine renewing its keys: vouched by the identity key in force
    assert choose_basis(link("b", vouched_by="a identity"), bound) == Basis.VOUCHED
    # once an identity key is in force the node key vouches for nothing
    assert choose_basis(link("b", vouched_by="a node"), bound) == Basis.REPLACES
    # an outpoint off the list that has had a key is never new again
    lapsed = NodeState(OUTPOINT, identity_key=public("a identity"), in_force_since=420)
    assert choose_basis(link("b"), lapsed) == Basis.REPLACES


async def test_a_manager_binds_a_new_node() -> None:
    chain = TableChain(NodeState(OUTPOINT, delegates=MANAGED))
    done = await bind(chain, MANAGER, link("a"), COLLATERAL, now=NOW)
    assert (done.outcome, done.sent, done.basis, done.sign_height) == (
        "sent",
        True,
        "new",
        HEIGHT,
    )
    expected = StartV7(
        OUTPOINT,
        public("a node"),
        HEIGHT,
        NOW,
        collateral_pubkey=COLLATERAL.pubkey,
        link=link("a"),
        basis=Basis.NEW,
        by_delegate=True,
    ).sign(MANAGER)
    assert chain.sent == [expected] and done.transaction == expected.hex()


async def test_a_binding_can_be_built_without_being_sent() -> None:
    chain = TableChain(NodeState(OUTPOINT, delegates=MANAGED))
    done = await bind(chain, MANAGER, link("a"), COLLATERAL, send=False, now=NOW)
    assert (
        (done.outcome, done.sent) == ("built", False)
        and done.transaction
        and not chain.sent
    )


async def test_nothing_is_signed_for_a_bad_link_or_an_outpoint_not_named() -> None:
    good = link("a")
    forged = NodeLink(
        good.outpoint, good.identity_key, good.proof, public("x draw"), good.node_key
    )
    chain = TableChain(NodeState(OUTPOINT, delegates=MANAGED))
    assert (await bind(chain, MANAGER, forged, COLLATERAL)).outcome.startswith(
        "refused: the link's proof"
    )

    restart_only = [Delegate(public("signer manager"), Role.RESTART)]
    for delegates in (
        [],
        restart_only,
        [Delegate(public("other manager"), Role.MANAGER)],
    ):
        chain = TableChain(NodeState(OUTPOINT, delegates=delegates))
        done = await bind(chain, MANAGER, good, COLLATERAL)
        assert done.outcome == "refused: the manager key is not named for this outpoint"
        assert not chain.sent and done.transaction is None


async def test_keys_the_chain_already_has_are_left_alone() -> None:
    in_force = NodeState(OUTPOINT, delegates=MANAGED, identity_key=public("a identity"))
    pending = NodeState(
        OUTPOINT, delegates=MANAGED, pending_identity_key=public("a identity")
    )
    for state in (in_force, pending):
        chain = TableChain(state)
        done = await bind(chain, MANAGER, link("a"), COLLATERAL)
        assert done.outcome.startswith("nothing to do") and not chain.sent


async def test_replacing_a_running_machine_is_refused_unless_asked_for() -> None:
    running = NodeState(
        OUTPOINT,
        listed=True,
        address="25.209.0.10:16127",
        node_key=public("a node"),
        delegates=MANAGED,
    )
    chain = TableChain(running)
    refused = await bind(chain, MANAGER, link("b"), COLLATERAL, now=NOW)
    assert refused.outcome.startswith(
        "refused: this would replace the machine now running the node at 25.209.0.10"
    )
    assert refused.basis == "replaces" and not chain.sent
    done = await bind(
        chain, MANAGER, link("b"), COLLATERAL, allow_replace=True, now=NOW
    )
    assert (done.outcome, done.basis) == ("sent", "replaces")
    # the running machine's own link is vouched and needs no such leave
    vouched = await bind(
        chain, MANAGER, link("a", vouched_by="a node"), COLLATERAL, now=NOW
    )
    assert (vouched.outcome, vouched.basis) == ("sent", "vouched")


async def test_a_multisig_collateral_is_named_by_its_redeem_script() -> None:
    script = (
        bytes.fromhex("5221")
        + public("cosigner one")
        + bytes.fromhex("21")
        + public("cosigner two")
        + bytes.fromhex("52ae")
    )
    chain = TableChain(NodeState(OUTPOINT, delegates=MANAGED))
    done = await bind(
        chain, MANAGER, link("a"), Collateral(redeem_script=script), now=NOW
    )
    assert done.outcome == "sent" and script.hex() in (done.transaction or "")
    # P2SH and the identity and delegates bits
    assert chain.sent[0][5:9] == (0x0302).to_bytes(4, "little")


async def test_the_view_says_where_each_outpoint_stands() -> None:
    other = Outpoint(hashlib.sha256(b"signer other").hexdigest(), 0)
    bound = NodeState(
        OUTPOINT,
        listed=True,
        address="25.209.0.10:16127",
        delegates=MANAGED,
        identity_key=public("a identity"),
        in_force_since=431,
    )
    chain = TableChain(bound)
    first, second = await view(chain, public("signer manager"), [OUTPOINT, other])
    assert (first.standing, first.role, first.in_force_since) == (
        Standing.BOUND,
        "manager",
        431,
    )
    assert first.identity_fingerprint == link("a").fingerprint()
    assert (second.standing, second.role, second.listed) == (
        Standing.NOT_NAMED,
        None,
        False,
    )
    assert (
        standing(NodeState(OUTPOINT, delegates=MANAGED), public("signer manager"))
        == Standing.UNBOUND
    )
    pending = NodeState(
        OUTPOINT, delegates=MANAGED, pending_identity_key=public("b identity")
    )
    assert standing(pending, public("signer manager")) == Standing.PENDING
    assert first.json()["standing"] == "bound"


def test_the_chains_answers_become_one_state() -> None:
    state = node_state(
        OUTPOINT,
        {
            "ip": "25.209.0.10:16127",
            "pubkey": public("a node").hex(),
            "identity_pending_pubkey": public("b identity").hex(),
            "identity_pending_since": 440,
        },
        {
            "identity_pubkey": public("a identity").hex(),
            "draw_pubkey": public("a draw").hex(),
            "in_force_since": 431,
        },
        {
            "has_delegates": True,
            "delegate_keys": [public("signer manager").hex(), public("r").hex()],
            "roles": ["manager", "restart"],
        },
    )
    assert (
        state.listed
        and state.address == "25.209.0.10:16127"
        and state.in_force_since == 431
    )
    assert (state.identity_key, state.pending_identity_key, state.pending_since) == (
        public("a identity"),
        public("b identity"),
        440,
    )
    assert (
        state.role_of(public("signer manager")) == Role.MANAGER
        and state.role_of(public("r")) == Role.RESTART
    )
    empty = node_state(
        OUTPOINT,
        None,
        {"identity_pubkey": "", "draw_pubkey": "", "in_force_since": 0},
        {"has_delegates": False},
    )
    assert empty == NodeState(OUTPOINT)
    # delegates set before roles existed are restart keys
    old = node_state(OUTPOINT, None, {}, {"delegate_keys": [public("r").hex()]})
    assert old.role_of(public("r")) == Role.RESTART


def test_the_manager_link_names_the_owners_outpoints() -> None:
    made = manager_link(MANAGER, [OUTPOINT])
    assert made.proof_verifies() and made.manager_key == public("signer manager")
