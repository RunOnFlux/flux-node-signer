"""The version 7 formats against the vectors of the wallet format specification.

Keys are SHA256(seed) mod (n - 1) + 1 for the seeds named; signatures are RFC 6979,
so every byte below is reproduced. The hex is laid out line for line as the
specification prints it.
"""

import hashlib

import pytest

from flux_node_signer.crypto import (
    SECP256K1_ORDER,
    privkey_to_pubkey,
    sign_bare,
    verify_bare,
)
from flux_node_signer.exceptions import ValidationError
from flux_node_signer.identity import (
    LABEL_PROOF,
    LABEL_VOUCH,
    NO_DELEGATES,
    Basis,
    Delegate,
    DelegateTxV7,
    ManagerLink,
    NodeLink,
    Outpoint,
    Role,
    StartV7,
    delegates_hash,
    fingerprint,
    identity_digest,
    manager_hash,
    txid,
)

SIG_TIME = 1795000000
SIGN_HEIGHT = 3200000


def secret(seed: str) -> bytes:
    number = int.from_bytes(hashlib.sha256(seed.encode()).digest(), "big")
    return (number % (SECP256K1_ORDER - 1) + 1).to_bytes(32, "big")


def public(seed: str) -> bytes:
    return privkey_to_pubkey(secret(seed), compressed=True)


COLLATERAL, IDENTITY, DRAW, NODE, MANAGER = (
    f"wallet-spec {name}"
    for name in ("collateral", "identity", "draw", "node", "manager")
)
OUTPOINT = Outpoint(hashlib.sha256(b"wallet-spec outpoint").hexdigest(), 0)
MULTISIG_OUTPOINT = Outpoint(
    hashlib.sha256(b"wallet-spec multisig outpoint").hexdigest(), 1
)
REDEEM_SCRIPT = bytes.fromhex(
    "52210360d25ed92df69fa4813e272dfd906484cc1e69f1de566dc4f2e66fe307178a492103f306d07414fe27879b1fb8"
    "19ab3e4ed48c329694cdcca3f98e7719931d4b113452ae"
)

PROOF = (
    "6a80700fadcf25d4f7a4afef5f4407b500c7ca3e41a3014f856b9a7ce6ce6ead35383892bb4250083eaabea385fc82bf"
    "413b481b77d9a0313595db03553f3dfb"
)
VOUCH = (
    "6e273f3f93468828912717f1f3803b2cf1c2e2ed02c58182bc15f119a162f3a44bfc2837aff39f03dcb539c379384f4a"
    "8a1e723b851a8310fcc6eabe54e62e06"
)
LINK = (
    "FLUXID1 3a27e50730bbcd1b69caa14a80e829be896aa981d35ca625266a59012dbc2d05:0 "
    "0279b6864bc95a88eb3f91611d5ec1a31397ace59801c003e9ade49d5830f50e66 "
    f"{PROOF} "
    "033bfb696841cdadf4a68a6f03fb96c1c826be077b2c04fe7d3f426948cf6f6b24 "
    "02929ca91adbb36086a573b026a2682ba7adaf45fb2506240cbbab1e5107338cff "
    f"{VOUCH}"
)
MULTISIG_PROOF = (
    "b35e1c1560d58d31ad954ce3069e4adc30f4a151d9f2ffe09e475bee4dc13520382527dbb08a721cec655a4dff98d8ea"
    "7975af9109508a36300147775b912691"
)
MANAGER_LINK = (
    "FLUXMGR1 021dac4faf38d9110dcd52e5434ca4b1f47276df744f3ae3753c945a616423bd2b "
    "9820fa3b86c327d344b77a35550f368ef0c6d591f868f4741cce858f08a839394d331e5706812d01c1ee522630596ba5"
    "facea28be415c4956f7e5ecd51aee0cc "
    "3a27e50730bbcd1b69caa14a80e829be896aa981d35ca625266a59012dbc2d05:0"
)

START_NEW = (
    "07000000020102000000d43000052dbc2d01596a2625a65cd381a96a89be29e8804aa1ca691bcdbb3007e5273a000000"
    "002103a0af5d06f4a1be944b203994f7ba86a87834555ec1e02a854a7f10d57e068d102102929ca91adbb36086a573b0"
    "26a2682ba7adaf45fb2506240cbbab1e5107338cffc086fd6a0279b6864bc95a88eb3f91611d5ec1a31397ace59801c0"
    "03e9ade49d5830f50e666a80700fadcf25d4f7a4afef5f4407b500c7ca3e41a3014f856b9a7ce6ce6ead35383892bb42"
    "50083eaabea385fc82bf413b481b77d9a0313595db03553f3dfb033bfb696841cdadf4a68a6f03fb96c1c826be077b2c"
    "04fe7d3f426948cf6f6b2401411f12b9026d2fc2485d6b172d8a9a5e380e63aacdafc00a6f149f4d299df6a07f3920ee"
    "898aa27d9c71bbbfae6e8d3dab56facc084e94d55b899336de587e240399"
)
START_VOUCHED = (
    "07000000020102000000d43000052dbc2d01596a2625a65cd381a96a89be29e8804aa1ca691bcdbb3007e5273a000000"
    "002103a0af5d06f4a1be944b203994f7ba86a87834555ec1e02a854a7f10d57e068d102102929ca91adbb36086a573b0"
    "26a2682ba7adaf45fb2506240cbbab1e5107338cffc086fd6a0279b6864bc95a88eb3f91611d5ec1a31397ace59801c0"
    "03e9ade49d5830f50e666a80700fadcf25d4f7a4afef5f4407b500c7ca3e41a3014f856b9a7ce6ce6ead35383892bb42"
    "50083eaabea385fc82bf413b481b77d9a0313595db03553f3dfb033bfb696841cdadf4a68a6f03fb96c1c826be077b2c"
    "04fe7d3f426948cf6f6b24026e273f3f93468828912717f1f3803b2cf1c2e2ed02c58182bc15f119a162f3a44bfc2837"
    "aff39f03dcb539c379384f4a8a1e723b851a8310fcc6eabe54e62e06411f35f5ad340a7f606f08183e239db447993744"
    "56269dd3f50c255dc8df84c458761560bcd85c93d011ea4688043fe286b9909297657fd49b588e935ab731760da6"
)
START_REPLACES = (
    "07000000020102000000d43000052dbc2d01596a2625a65cd381a96a89be29e8804aa1ca691bcdbb3007e5273a000000"
    "002103a0af5d06f4a1be944b203994f7ba86a87834555ec1e02a854a7f10d57e068d102102929ca91adbb36086a573b0"
    "26a2682ba7adaf45fb2506240cbbab1e5107338cffc086fd6a0279b6864bc95a88eb3f91611d5ec1a31397ace59801c0"
    "03e9ade49d5830f50e666a80700fadcf25d4f7a4afef5f4407b500c7ca3e41a3014f856b9a7ce6ce6ead35383892bb42"
    "50083eaabea385fc82bf413b481b77d9a0313595db03553f3dfb033bfb696841cdadf4a68a6f03fb96c1c826be077b2c"
    "04fe7d3f426948cf6f6b2403412016a77303c02156e5063b24ab3c036d8ec7d577bd6d888291799a0b1117326913247f"
    "d899430464756e393a659c857ff3c4728e00d480e13b3813f07d91a8dbf8"
)
DELEGATE_TX = (
    "07000000120100000000d43000052dbc2d01596a2625a65cd381a96a89be29e8804aa1ca691bcdbb3007e5273a000000"
    "002103a0af5d06f4a1be944b203994f7ba86a87834555ec1e02a854a7f10d57e068d10c086fd6a02010121021dac4faf"
    "38d9110dcd52e5434ca4b1f47276df744f3ae3753c945a616423bd2b0101000000000000000000000000000000000000"
    "00000000000000000000000000004120340b985fdc92cc0220a4438ce52724c87ac16c3146af8ef8e51d115ebbd96676"
    "22f007007c45425d92354bff1687a8e5f2b35fbc6c72c9355a97d3e57c91c9fc"
)
MULTISIG_START_NEW = (
    "07000000020202000000d4300005856b62f55874e3c4512f8e843f2df017c0bbb8326ad9c34be9195c62942c6f010000"
    "002102929ca91adbb36086a573b026a2682ba7adaf45fb2506240cbbab1e5107338cff4752210360d25ed92df69fa481"
    "3e272dfd906484cc1e69f1de566dc4f2e66fe307178a492103f306d07414fe27879b1fb819ab3e4ed48c329694cdcca3"
    "f98e7719931d4b113452aec086fd6a0279b6864bc95a88eb3f91611d5ec1a31397ace59801c003e9ade49d5830f50e66"
    "b35e1c1560d58d31ad954ce3069e4adc30f4a151d9f2ffe09e475bee4dc13520382527dbb08a721cec655a4dff98d8ea"
    "7975af9109508a36300147775b912691033bfb696841cdadf4a68a6f03fb96c1c826be077b2c04fe7d3f426948cf6f6b"
    "2401411f086c10365980c42d35f48ac4287647c1edc82646aeb64d4fc3cf39b3e11e845d64848a99ed26e405ad295815"
    "d5abe626436f35d8cfd208825ffb6567c0e22028"
)
MULTISIG_DELEGATE_TX = (
    "07000000120200000000d4300005856b62f55874e3c4512f8e843f2df017c0bbb8326ad9c34be9195c62942c6f010000"
    "004752210360d25ed92df69fa4813e272dfd906484cc1e69f1de566dc4f2e66fe307178a492103f306d07414fe27879b"
    "1fb819ab3e4ed48c329694cdcca3f98e7719931d4b113452aec086fd6a02010121021dac4faf38d9110dcd52e5434ca4"
    "b1f47276df744f3ae3753c945a616423bd2b010100000000000000000000000000000000000000000000000000000000"
    "000000004120ad0709ddc7fc9b35c4b730dca4fe609431a7c473269e7426b46b0f8132f257ca03d35f63d83344b59486"
    "82b56f9c4537714208e6d18d82b4e86fd2aa2cbb8bf6"
)


@pytest.fixture
def link() -> NodeLink:
    return NodeLink.parse(LINK)


def test_the_seeds_give_the_specifications_keys() -> None:
    assert (
        public(COLLATERAL).hex()
        == "03a0af5d06f4a1be944b203994f7ba86a87834555ec1e02a854a7f10d57e068d10"
    )
    assert (
        public(MANAGER).hex()
        == "021dac4faf38d9110dcd52e5434ca4b1f47276df744f3ae3753c945a616423bd2b"
    )
    assert OUTPOINT.serialize().hex() == (
        "052dbc2d01596a2625a65cd381a96a89be29e8804aa1ca691bcdbb3007e5273a00000000"
    )


def test_a_link_is_read_and_written_as_one_line_and_by_field(link: NodeLink) -> None:
    assert link.outpoint == OUTPOINT
    assert (link.identity_key, link.draw_key, link.node_key) == (
        public(IDENTITY),
        public(DRAW),
        public(NODE),
    )
    assert link.line() == LINK
    fields = {
        "outpoint": str(OUTPOINT),
        "identitykey": public(IDENTITY).hex(),
        "proof": PROOF,
        "drawkey": public(DRAW).hex(),
        "nodekey": public(NODE).hex(),
        "vouch": VOUCH,
    }
    assert NodeLink.from_fields(fields) == link
    del fields["vouch"]
    assert NodeLink.from_fields(fields).vouch is None
    assert NodeLink.from_fields(fields).line() == LINK.rsplit(" ", 1)[0]


def test_the_key_set_hash_the_digests_and_the_fingerprints(link: NodeLink) -> None:
    key_set = link.key_set_hash()
    assert (
        key_set.hex()
        == "9d1cfba213a3d136315203223d3e0052606f3639920e77439b2217dbddc49fce"
    )
    assert identity_digest(LABEL_PROOF, key_set).hex() == (
        "3890d89e6c6aac3ad587bd19defaff76cf09d3ae0ce479a4d9ee003b5293d285"
    )
    assert identity_digest(LABEL_VOUCH, key_set).hex() == (
        "67c46c2645ae05e0074320844b40fe54aacd08fb991de4bebade8dce9e17edfb"
    )
    assert link.fingerprint() == "cbba c6ec b3b6 1c06 f87f fadf fcbf 9f17"
    assert fingerprint(public(MANAGER)) == "0a2e 0718 47fb b0e6 32c5 afa1 617f 273e"


def test_the_proof_and_the_vouch_are_the_identity_keys_and_the_node_keys(
    link: NodeLink,
) -> None:
    key_set = link.key_set_hash()
    assert (
        sign_bare(identity_digest(LABEL_PROOF, key_set), secret(IDENTITY)).hex()
        == PROOF
    )
    assert sign_bare(identity_digest(LABEL_VOUCH, key_set), secret(NODE)).hex() == VOUCH
    assert link.proof_verifies()
    assert link.vouched_by(public(NODE))
    assert not link.vouched_by(public(IDENTITY))
    assert not NodeLink.parse(LINK.rsplit(" ", 1)[0]).vouched_by(public(NODE))


def test_a_link_with_a_key_swapped_fails_its_proof(link: NodeLink) -> None:
    swapped = NodeLink(
        link.outpoint, link.identity_key, link.proof, public(MANAGER), link.node_key
    )
    assert not swapped.proof_verifies()
    moved = NodeLink(
        MULTISIG_OUTPOINT, link.identity_key, link.proof, link.draw_key, link.node_key
    )
    assert not moved.proof_verifies()


def test_a_signature_with_s_in_the_upper_half_is_refused(link: NodeLink) -> None:
    digest = identity_digest(LABEL_PROOF, link.key_set_hash())
    r, s = link.proof[:32], int.from_bytes(link.proof[32:], "big")
    high = r + (SECP256K1_ORDER - s).to_bytes(32, "big")
    assert verify_bare(digest, link.proof, link.identity_key)
    assert not verify_bare(digest, high, link.identity_key)


@pytest.mark.parametrize(
    "line",
    [
        LINK + " ",
        LINK.replace("FLUXID1", "FLUXID2"),
        LINK.upper().replace("FLUXID1", "FLUXID1"),
        LINK.replace(":0 ", ":00 "),
        LINK.replace(":0 ", ":4294967296 "),
        LINK.replace("  ", " ").replace(" 0279", "  0279"),
        LINK[:-2],
        LINK + " 00",
        " ".join(LINK.split(" ")[:5]),
        # an x coordinate that is on no point of the curve
        LINK.replace(public(DRAW).hex(), "02" + "00" * 31 + "05"),
    ],
)
def test_anything_but_an_exact_link_is_refused(line: str) -> None:
    with pytest.raises(ValidationError):
        NodeLink.parse(line)


def test_a_start_on_each_basis(link: NodeLink) -> None:
    def start(basis: Basis) -> bytes:
        return StartV7(
            OUTPOINT,
            public(NODE),
            SIGN_HEIGHT,
            SIG_TIME,
            collateral_pubkey=public(COLLATERAL),
            link=link,
            basis=basis,
        ).sign(secret(COLLATERAL))

    assert start(Basis.NEW).hex() == START_NEW
    assert (
        txid(start(Basis.NEW))
        == "54ac6c256daa2a52b982d6f03c9e4ea6006c5d463cd5fe9ff10c10cd7f283de9"
    )
    assert start(Basis.VOUCHED).hex() == START_VOUCHED
    assert (
        txid(start(Basis.VOUCHED))
        == "43dc1958b1a41b36ed6b30280cbb3c9e3f867291242808abe9ee2c41ed7ac568"
    )
    assert start(Basis.REPLACES).hex() == START_REPLACES
    assert (
        txid(start(Basis.REPLACES))
        == "47dc92c11ed935913294cfa6af27266c531b70ac34f4d5ec00512b8b2ce53f89"
    )


def test_a_start_is_refused_before_it_is_built_when_it_contradicts_itself(
    link: NodeLink,
) -> None:
    common = {
        "outpoint": OUTPOINT,
        "node_key": public(NODE),
        "sign_height": SIGN_HEIGHT,
        "sig_time": SIG_TIME,
    }
    with pytest.raises(ValidationError):
        StartV7(**common, link=link, basis=Basis.NEW)
    with pytest.raises(ValidationError):
        StartV7(
            **common, collateral_pubkey=public(COLLATERAL), redeem_script=REDEEM_SCRIPT
        )
    with pytest.raises(ValidationError):
        StartV7(**common, collateral_pubkey=public(COLLATERAL), basis=Basis.NEW)
    unvouched = NodeLink.parse(LINK.rsplit(" ", 1)[0])
    with pytest.raises(ValidationError):
        StartV7(
            **common,
            collateral_pubkey=public(COLLATERAL),
            link=unvouched,
            basis=Basis.VOUCHED,
        )
    with pytest.raises(ValidationError):
        StartV7(
            **{**common, "outpoint": MULTISIG_OUTPOINT},
            collateral_pubkey=public(COLLATERAL),
            link=link,
            basis=Basis.NEW,
        )


def test_a_start_with_the_keys_in_force_carries_them_on_basis_none(
    link: NodeLink,
) -> None:
    common = {
        "outpoint": OUTPOINT,
        "node_key": public(NODE),
        "sign_height": SIGN_HEIGHT,
        "sig_time": SIG_TIME,
        "collateral_pubkey": public(COLLATERAL),
    }
    setting = StartV7(**common, link=link, basis=Basis.NEW).unsigned()
    carrying = StartV7(**common, link=link).unsigned()
    # the same bytes but the basis, the last of the identity fields
    assert carrying[:-1] == setting[:-1] and (carrying[-1], setting[-1]) == (0, 1)
    # with no link a start has no identity bit and ends at its sigTime
    bare = StartV7(**common).unsigned()
    assert bare[5:9] == (0x0001).to_bytes(4, "little")
    assert bare.endswith(SIG_TIME.to_bytes(4, "little"))


def test_a_start_a_delegate_signs_says_so_and_differs_only_there(
    link: NodeLink,
) -> None:
    common = {
        "outpoint": OUTPOINT,
        "node_key": public(NODE),
        "sign_height": SIGN_HEIGHT,
        "sig_time": SIG_TIME,
        "collateral_pubkey": public(COLLATERAL),
        "link": link,
        "basis": Basis.NEW,
    }
    owner = StartV7(**common).unsigned()
    manager = StartV7(**common, by_delegate=True).unsigned()
    # the delegates bit; then: a delegate signs, a signing record, no set replaced
    assert manager[5:9] == (0x0301).to_bytes(4, "little") and owner[5:9] == (
        0x0201
    ).to_bytes(4, "little")
    assert manager[:5] + manager[9 : len(owner)] == owner[:5] + owner[9:]
    assert manager[len(owner) :] == b"\x01\x02\x02" + bytes(32)


def test_the_delegates_hash_and_the_delegate_transaction() -> None:
    managed = [Delegate(public(MANAGER), Role.MANAGER)]
    assert (
        delegates_hash(managed).hex()
        == "39407d4993993d9239a8f70e7fdfbb08464b387259cfd0cbcdad975580d354c6"
    )
    tx = DelegateTxV7(
        OUTPOINT,
        SIGN_HEIGHT,
        SIG_TIME,
        managed,
        NO_DELEGATES,
        collateral_pubkey=public(COLLATERAL),
    ).sign(secret(COLLATERAL))
    assert tx.hex() == DELEGATE_TX
    assert (
        txid(tx) == "fce29cffb8fa5035f1490b901776af52fc984a2a42c9ae5fb8f56aa39714cc65"
    )
    with pytest.raises(ValidationError):
        DelegateTxV7(
            OUTPOINT,
            SIGN_HEIGHT,
            SIG_TIME,
            managed * 5,
            collateral_pubkey=public(COLLATERAL),
        ).sign(secret(COLLATERAL))


def test_a_multisig_collateral() -> None:
    link = NodeLink(
        MULTISIG_OUTPOINT,
        public(IDENTITY),
        bytes.fromhex(MULTISIG_PROOF),
        public(DRAW),
        public(NODE),
    )
    assert link.proof_verifies()
    start = StartV7(
        MULTISIG_OUTPOINT,
        public(NODE),
        SIGN_HEIGHT,
        SIG_TIME,
        redeem_script=REDEEM_SCRIPT,
        link=link,
        basis=Basis.NEW,
    ).sign(secret("wallet-spec cosigner one"))
    assert start.hex() == MULTISIG_START_NEW
    assert (
        txid(start)
        == "d8c00eeff4a59ac2ab26eebb4387ffecc408727f1f664ed31ae88e337728b27b"
    )
    delegate = DelegateTxV7(
        MULTISIG_OUTPOINT,
        SIGN_HEIGHT,
        SIG_TIME,
        [Delegate(public(MANAGER), Role.MANAGER)],
        redeem_script=REDEEM_SCRIPT,
    ).sign(secret("wallet-spec cosigner two"))
    assert delegate.hex() == MULTISIG_DELEGATE_TX
    assert (
        txid(delegate)
        == "4e0612e8fd3fe7baab85fecedcb6570ade57bbf229e4bf08616bbc930861428d"
    )


def test_a_manager_link() -> None:
    link = ManagerLink.make(secret(MANAGER), [OUTPOINT])
    assert manager_hash(public(MANAGER), [OUTPOINT]).hex() == (
        "123b4b7242a8302f0d69760affa45c2273ac1410bf52a4f31294eca2a538551a"
    )
    assert link.line() == MANAGER_LINK
    assert ManagerLink.parse(MANAGER_LINK) == link and link.proof_verifies()
    assert ManagerLink.from_fields(link.fields()) == link
    assert link.fields()["fingerprint"] == "0a2e 0718 47fb b0e6 32c5 afa1 617f 273e"
    # an outpoint added or changed fails the proof
    widened = ManagerLink(link.manager_key, link.proof, (OUTPOINT, MULTISIG_OUTPOINT))
    assert not widened.proof_verifies()
    with pytest.raises(ValidationError):
        ManagerLink.parse(MANAGER_LINK + " " + str(OUTPOINT))
    with pytest.raises(ValidationError):
        ManagerLink.parse(" ".join(MANAGER_LINK.split(" ")[:3]))
