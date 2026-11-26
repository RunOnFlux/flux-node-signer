"""Cryptographic operations for fluxnode transactions."""

import hashlib

import base58
from coincurve import PrivateKey, PublicKey


def decode_wif(wif: str) -> tuple[bytes, bool]:
    """
    Decode WIF (Wallet Import Format) to private key bytes and compressed flag.

    Args:
        wif: WIF-encoded private key string

    Returns:
        Tuple of (private_key_bytes, is_compressed)

    Raises:
        ValueError: If WIF is invalid
    """
    try:
        decoded = base58.b58decode_check(wif)
    except Exception as e:
        raise ValueError(f"Invalid WIF format: {e}") from e

    if len(decoded) < 33:
        raise ValueError("WIF too short")

    # First byte is version
    version = decoded[0]

    # Check for valid Flux/Bitcoin version bytes
    # 0x80 = mainnet, 0xEF = testnet
    if version not in (0x80, 0xEF):
        raise ValueError(f"Invalid WIF version byte: {version:#x}")

    # Next 32 bytes are the private key
    privkey = decoded[1:33]

    # If there's a 34th byte and it's 0x01, the key is compressed
    compressed = len(decoded) == 34 and decoded[33] == 0x01

    return privkey, compressed


def privkey_to_pubkey(privkey: bytes, compressed: bool = True) -> bytes:
    """
    Derive public key from private key.

    Args:
        privkey: 32-byte private key
        compressed: Whether to return compressed public key (33 bytes vs 65 bytes)

    Returns:
        Public key bytes (33 bytes if compressed, 65 bytes if uncompressed)
    """
    pk = PrivateKey(privkey)
    pubkey = pk.public_key
    return pubkey.format(compressed=compressed)


SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def sign_compact(message_hash: bytes, privkey: bytes, compressed: bool = True) -> bytes:
    """A 65-byte recoverable signature of a 32-byte hash: a header byte of 27 +
    recovery id, plus 4 when the signing key's public form is compressed, then r and
    s (32 bytes each, big-endian, s in the lower half of the curve order)."""
    signature = PrivateKey(privkey).sign_recoverable(message_hash, hasher=None)
    header = 27 + signature[64] + (4 if compressed else 0)
    return bytes([header]) + signature[:64]


def sign_bare(message_hash: bytes, privkey: bytes) -> bytes:
    """A 64-byte signature of a 32-byte hash: r then s, s in the lower half of the
    order."""
    return PrivateKey(privkey).sign_recoverable(message_hash, hasher=None)[:64]


def _der_integer(value: bytes) -> bytes:
    body = value.lstrip(b"\x00") or b"\x00"
    if body[0] & 0x80:
        body = b"\x00" + body
    return b"\x02" + bytes([len(body)]) + body


def verify_bare(message_hash: bytes, signature: bytes, pubkey: bytes) -> bool:
    """Whether `signature` (64 bytes, r then s) is `pubkey`'s over the hash. A
    signature whose s is in the upper half of the curve order is refused."""
    if (
        len(signature) != 64
        or int.from_bytes(signature[32:], "big") > SECP256K1_ORDER // 2
    ):
        return False
    body = _der_integer(signature[:32]) + _der_integer(signature[32:])
    try:
        return PublicKey(pubkey).verify(
            b"\x30" + bytes([len(body)]) + body, message_hash, hasher=None
        )
    except ValueError:
        return False


def verify_compact_signature(
    message_hash: bytes, signature: bytes, expected_pubkey: bytes
) -> bool:
    """
    Verify a Bitcoin compact signature against an expected public key.

    Bitcoin compact format: [27/31 + recovery_id, r (32 bytes), s (32 bytes)]
    coincurve format: [r (32 bytes), s (32 bytes), recovery_id (1 byte)]

    Args:
        message_hash: 32-byte hash that was signed
        signature: 65-byte Bitcoin compact signature
        expected_pubkey: Expected public key (33 or 65 bytes)

    Returns:
        True if signature is valid and matches expected pubkey
    """
    if len(signature) != 65:
        return False

    try:
        # Extract from Bitcoin compact format: [compact_byte, r, s]
        compact_byte = signature[0]
        r = signature[1:33]
        s = signature[33:65]

        # Decode recovery ID:
        # 27-30: uncompressed, recovery_id = compact_byte - 27
        # 31-34: compressed, recovery_id = compact_byte - 31
        if 31 <= compact_byte <= 34:
            recovery_id = compact_byte - 31  # Compressed
        elif 27 <= compact_byte <= 30:
            recovery_id = compact_byte - 27  # Uncompressed
        else:
            return False  # Invalid compact format

        # Reconstruct coincurve format: [r, s, recovery_id]
        coincurve_sig = r + s + bytes([recovery_id])

        # Recover public key from signature
        recovered_pubkey = PublicKey.from_signature_and_message(
            coincurve_sig, message_hash, hasher=None
        )

        # Compare with expected pubkey
        # Normalize both to compressed format for comparison
        expected = PublicKey(expected_pubkey).format(compressed=True)
        recovered = recovered_pubkey.format(compressed=True)

        return expected == recovered

    except Exception:
        return False


def sha256(data: bytes) -> bytes:
    """
    Compute SHA256 hash.

    Args:
        data: Data to hash

    Returns:
        32-byte hash
    """
    return hashlib.sha256(data).digest()


def hash256(data: bytes) -> bytes:
    """
    Compute double SHA256 hash (SHA256(SHA256(data))).

    This is the standard Bitcoin/Flux hash function.

    Args:
        data: Data to hash

    Returns:
        32-byte hash
    """
    return sha256(sha256(data))


def ripemd160(data: bytes) -> bytes:
    """
    Compute RIPEMD160 hash.

    Args:
        data: Data to hash

    Returns:
        20-byte hash
    """
    h = hashlib.new("ripemd160")
    h.update(data)
    return h.digest()


def hash160(data: bytes) -> bytes:
    """
    Compute HASH160 (RIPEMD160(SHA256(data))).

    This is used for Bitcoin/Flux addresses.

    Args:
        data: Data to hash

    Returns:
        20-byte hash
    """
    return ripemd160(sha256(data))


def pubkey_to_address(pubkey: bytes, version: int = 0x1CB8) -> str:
    """
    Convert public key to Flux address.

    Args:
        pubkey: Public key bytes (33 or 65 bytes)
        version: Address version bytes (default 0x1CB8 for Flux mainnet)

    Returns:
        Base58Check encoded address
    """
    # Hash the public key
    pubkey_hash = hash160(pubkey)

    # Add version bytes (Flux uses 2 bytes: 0x1C 0xB8)
    version_bytes = version.to_bytes(2, "big")
    versioned = version_bytes + pubkey_hash

    # Add checksum and encode
    checksum = hash256(versioned)[:4]
    address_bytes = versioned + checksum

    return base58.b58encode(address_bytes).decode("ascii")
