# flux-node-signer

Signs for fluxnodes from a workstation. It holds a delegate key an owner has named for
their nodes, reads the chain, and builds, signs and sends fluxnode transactions. It
reaches no node: what it needs from a node is handed to it.

## What it does

An owner names a key for a node (an outpoint) as a delegate, with one of two roles:

| Role | May |
|---|---|
| restart key | start the node again with the keys it has |
| manager key | that, and set the node's keys |

| Command | What it does |
|---|---|
| `generate-delegate-key` | makes a key and writes it encrypted (age, by passphrase) |
| `manager-link` | makes the link a manager gives an owner, who names the key from it in their wallet |
| `view` | reports where each outpoint stands for a manager key: not named, unbound, pending or bound |
| `bind` | binds nodes' keys from their links, with a version 7 start the manager key signs |
| `restart` | starts nodes that have left the list, with the keys they have (version 7) |
| `start`, `batch`, `build` | a version 6 delegated start, one node or many |
| `derive-pubkey`, `check-delegates`, `find-start-tx`, `test-connection` | helpers |

`manager-link`, `view`, `bind` and `restart` print one JSON document on standard output
and their errors on standard error, so a program can call them. The same operations
are a library: `flux_node_signer.signer` (`manager_link`, `view`, `bind`, `restart`)
over the formats in `flux_node_signer.identity`.

## A manager's work, end to end

The chain is a fluxd reached over JSON-RPC: `FLUX_RPC_HOST`, `FLUX_RPC_PORT`,
`FLUX_RPC_USERNAME`, `FLUX_RPC_PASSWORD`, or the `--rpc-*` options.

1. **Make the manager key**, once:

   ```bash
   flux-node-signer generate-delegate-key --name manager
   ```

2. **Give each owner a manager link** for their nodes. The owner's wallet reads it,
   shows the key's fingerprint, and names the key for those outpoints. The owner
   compares the fingerprint with the one you show them.

   ```bash
   flux-node-signer manager-link --key-file manager.key.age <txid>:<n> [<txid>:<n> ...]
   ```

   ```json
   {
    "line": "FLUXMGR1 <managerkey> <proof> <txid>:<n>",
    "managerkey": "<66 hex>",
    "fingerprint": "0a2e 0718 47fb b0e6 32c5 afa1 617f 273e",
    "proof": "<128 hex>",
    "outpoints": ["<txid>:<n>"]
   }
   ```

3. **See which outpoints name the key**, and the state of each node's keys:

   ```bash
   flux-node-signer view --manager-key <66 hex> <txid>:<n> [<txid>:<n> ...]
   ```

   Each entry's `standing` is `not-named`, `unbound`, `pending` (a start has set keys
   the node's machine has not confirmed with yet) or `bound`.

4. **Bind each node's keys.** A node's link is the line fluxd gives in
   `getfluxnodestatus` (`identity_link_text`, or by field in `identity_link`). The
   input is a JSON list:

   ```json
   [
    {"link": "FLUXID1 <txid>:<n> <identitykey> <proof> <drawkey> <nodekey> [<vouch>]",
     "collateral_pubkey": "<66 hex>"},
    {"link": {"outpoint": "<txid>:<n>", "identitykey": "...", "proof": "...",
              "drawkey": "...", "nodekey": "..."},
     "redeem_script": "<hex>"}
   ]
   ```

   ```bash
   flux-node-signer bind nodes.json --key-file manager.key.age [--dry-run]
   ```

   For each entry the tool checks the link's proof, reads the outpoint's state, and
   states the basis the chain will hold it to: `new` (the outpoint is off the list
   and has never had keys), `vouched` (the link is vouched by the key the chain shows
   for the node) or `replaces` (another machine takes the node over). It signs
   nothing for a link whose proof fails, for an outpoint the key is not a manager of,
   or for keys the chain already has. A `replaces` binding is refused unless
   `--allow-replace` is given. Each result carries the `outcome`, the `basis`, the
   start's `txid` and its hex. The command exits 2 when any entry was refused.

5. **Restart a node that has left the list**, by a restart key or a manager key:

   ```json
   [{"outpoint": "<txid>:<n>", "node_key": "<hex>", "collateral_pubkey": "<66 hex>"}]
   ```

   ```bash
   flux-node-signer restart nodes.json --key-file restart.key.age [--dry-run]
   ```

   The start carries the node's keys in force and the proof they were set with;
   `node_key` is the node key that proof covers.

A multisig collateral is named by its `redeem_script` in place of `collateral_pubkey`.

## Version 6 delegated starts

`start`, `batch` and `build` make the version 6 start a delegate signs. The sections
below describe them.

## Installation

### Prerequisites

- Python 3.13+
- [uv](https://github.com/astral-sh/uv) package manager
- Access to a Flux RPC node

### Install uv

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### Install flux-node-signer

```bash
# From PyPI
pip install flux-node-signer
```

Or install from source:

```bash
# Clone the repository
git clone https://github.com/RunOnFlux/flux-node-signer.git
cd flux-node-signer

# Install with uv
uv sync

# Or install in development mode
uv sync --dev
```

### Verify Installation

```bash
# Activate the virtual environment
source .venv/bin/activate

# Test the CLI
flux-node-signer --help
```

## Quick Start

### 1. Test RPC Connection

```bash
flux-node-signer test-connection --rpc-user <username> --rpc-password <password>
```

### 2. Start a Single Fluxnode

```bash
flux-node-signer start <collateral_txhash> \
  --fluxnode-privkey <fluxnode_wif> \
  --delegate-key <delegate_wif> \
  --rpc-user <username> \
  --rpc-password <password>
```

**Example:**

```bash
flux-node-signer start \
  1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d \
  --fluxnode-privkey KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn \
  --delegate-key L3MnxQhwxBvKiJ5TKxHgCdeWPRzkYSdXqXT3qYjG8aE9XfC7vZqQ \
  --rpc-user myuser \
  --rpc-password mypassword
```

### 3. Dry Run (Build but Don't Send)

```bash
flux-node-signer start <args> --dry-run
```

### 4. Decode Transaction

```bash
flux-node-signer start <args> --decode --dry-run
```

### 5. Batch Start Multiple Fluxnodes

Create a YAML file with your fluxnodes:

```yaml
# collaterals.yaml
fluxnodes:
  # Minimal example (collateral_index defaults to 0)
  - label: "node-1"
    collateral_txhash: "1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d0"
    delegate_key: "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
    fluxnode_pubkey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

  # Using fluxnode_privkey (pubkey will be derived)
  - label: "node-2"
    collateral_txhash: "2075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d0"
    collateral_index: 1
    delegate_key: "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
    fluxnode_privkey: "L3MnQhBwxvKiJ5TKxHgCdeWPRzkYSdXqXT3qYjG8aE9XfC7vZqQ"

  # Using encrypted delegate key file
  - label: "node-3"
    collateral_txhash: "3075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d0"
    delegate_key_file: "delegate.key.age"
    fluxnode_pubkey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
```

Then run:

```bash
# Using default API transport (no credentials needed)
flux-node-signer batch collaterals.yaml

# With encrypted key files (passphrase via stdin)
echo "mypassphrase" | flux-node-signer batch collaterals.yaml

# Or provide passphrase via option
flux-node-signer batch --passphrase "mypassphrase" collaterals.yaml
```

See `examples/collaterals.example.yaml` for more detailed examples.

## CLI Commands

### `start`

Start a single fluxnode.

```bash
flux-node-signer start [OPTIONS] COLLATERAL_TXHASH
```

**Required Options (one of each):**
- `--collateral-pubkey`: P2PKH collateral public key (hex, e.g. Zelcore `t1...`), OR
- `--collateral-redeemscript`: P2SH multisig collateral redeem script (hex, e.g. SSP `t3...`)
- `--fluxnode-pubkey`: Fluxnode public key (hex), OR
- `--fluxnode-privkey`: Fluxnode private key (WIF) - will derive pubkey
- `--delegate-key`: Delegate private key (WIF), OR
- `--delegate-key-file`: Path to delegate key file

**RPC Options:**
- `--rpc-user`: RPC username (required)
- `--rpc-password`: RPC password (required)

**Optional:**
- `--index`, `-i`: Collateral output index (default: 0)
- `--dry-run`, `-n`: Build transaction but don't send
- `--decode`: Decode transaction before sending
- `--host`: RPC host (default: 127.0.0.1)
- `--port`: RPC port (default: 16124)

**P2SH / SSP collateral:**

For a multisig collateral created through SSP (an address starting `t3...`), pass its
redeem script instead of a pubkey. SSP shows the Redeem Script in the node's details.

```bash
flux-node-signer start <collateral_txhash> \
  --collateral-redeemscript <redeem_script_hex> \
  --fluxnode-privkey <fluxnode_wif> \
  --delegate-key-file delegate.key.age
```

`batch` collaterals (via YAML) only support P2PKH (`--collateral-pubkey`) collateral.

### `batch`

Start multiple fluxnodes from a YAML file.

```bash
flux-node-signer batch [OPTIONS] YAML_FILE
```

**Options:**
- `--dry-run`, `-n`: Build transactions but don't send
- `--continue-on-error`: Continue if a transaction fails (default: true)
- `--passphrase`, `-p`: Passphrase for encrypted key files (applies to all files in batch)
- `--transport`, `-t`: Transport method: 'api' (default) or 'rpc'
- `--host`: RPC host (only for --transport rpc, default: 127.0.0.1)
- `--port`: RPC port (only for --transport rpc, default: 16124)
- `--rpc-user`: RPC username (only for --transport rpc)
- `--rpc-password`: RPC password (only for --transport rpc)

**Encryption Support:**

If your YAML file uses encrypted delegate key files (`.key.age`), provide the passphrase via:

1. Command-line option:
```bash
flux-node-signer batch --passphrase "mypassphrase" collaterals.yaml
```

2. Stdin (for scripting):
```bash
echo "mypassphrase" | flux-node-signer batch collaterals.yaml
```

**Note:** The same passphrase is used for ALL encrypted key files in the batch. If your files use different passphrases, run multiple batch commands.

### `build`

Build transaction and output hex only (for scripting).

```bash
flux-node-signer build COLLATERAL_TXHASH [OPTIONS]
```

**Required Options (one of each):**
- `--collateral-pubkey`: P2PKH collateral public key (hex), OR
- `--collateral-redeemscript`: P2SH multisig collateral redeem script (hex)
- `--fluxnode-pubkey`: Fluxnode public key (hex), OR
- `--fluxnode-privkey`: Fluxnode private key (WIF) - will derive pubkey
- `--delegate-key`: Delegate private key (WIF), OR
- `--delegate-key-file`: Path to delegate key file

**Optional:**
- `--index`, `-i`: Collateral output index (default: 0)

Outputs raw hex to stdout (no formatting).

### `derive-pubkey`

Derive public key from a WIF private key.

```bash
flux-node-signer derive-pubkey WIF_PRIVATE_KEY
```

This utility helps you convert your private keys to public keys. Very useful when you have:
- Collateral private key → need collateral public key
- Fluxnode private key → need fluxnode public key

**Example:**
```bash
$ flux-node-signer derive-pubkey KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn
✓ Derived public key:
0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
```

### `test-connection`

Test RPC connection to Flux daemon.

```bash
flux-node-signer test-connection [OPTIONS]
```

## Getting Your Keys

This section explains how to get all the required parameters for the `start` command.

### 1. Collateral Transaction Hash & Index

From your wallet that sent the collateral:

```bash
# Find your collateral transaction
flux-cli listtransactions

# Get details
flux-cli gettransaction <txid>
```

Or from Zelcore: Check your transaction history for the 1000/12500/40000 FLUX send.

- **collateral_txhash**: The transaction ID (64 hex characters)
- **collateral_index**: Usually `0` or `1` (which output in the transaction)

### 2. Collateral Public Key

You need the **public key** for the address that holds the collateral.

**Option A: From Zelcore**
Zelcore doesn't easily show public keys, so you'll need the private key:
1. Export the private key from Zelcore for your collateral address
2. Use our utility:
```bash
flux-node-signer derive-pubkey <your_collateral_private_key_WIF>
```

**Option B: From flux-cli**
If you have the collateral address in flux-cli wallet:
```bash
# Get the address that holds collateral
flux-cli getaddressesbyaccount ""

# Get the private key (KEEP THIS SECURE!)
flux-cli dumpprivkey <your_collateral_address>

# Derive public key
flux-node-signer derive-pubkey <WIF_from_above>
```

### 3. Delegate Private Key

This is a **new key** you generate just for signing START transactions. You can:

**Option A: Generate with flux-cli**
```bash
# Generate a new key pair
flux-cli getnewaddress

# Export the private key
flux-cli dumpprivkey <new_address>
```

**Option B: Use your collateral private key** (simpler but less secure)
You can use the same WIF as your collateral private key. This is fine for testing.

The `delegate_key` parameter expects WIF format directly (e.g., `KwDi...`)

### 4. Fluxnode Public Key

Each fluxnode needs its own identity key.

**Option A: From your fluxnode**
If you're running a fluxnode:
```bash
# On the fluxnode server
flux-cli getfluxnodestatus | grep pubkey
```

**Option B: Generate new keys**
```bash
# Generate a new address
flux-cli getnewaddress

# Dump the private key
flux-cli dumpprivkey <address>

# Derive the public key
flux-node-signer derive-pubkey <WIF_private_key>
```

For multi-node benchmarks, generate one key pair per node.

### Summary: What You Actually Need

```bash
# 1. Find your collateral transaction
collateral_txhash="abc123..."  # From wallet/blockchain

# 2. Get your RPC credentials
rpc_user=$(grep rpcuser ~/.flux/flux.conf | cut -d= -f2)
rpc_password=$(grep rpcpassword ~/.flux/flux.conf | cut -d= -f2)

# 3. Delegate key (can be same as collateral for simplicity)
delegate_key="L..."  # Export from Zelcore or flux-cli

# 4. Fluxnode privkey (generate new for each node)
fluxnode_privkey="K..."  # Generate with flux-cli getnewaddress

# 5. Build the transaction (pubkey will be derived automatically)
flux-node-signer start \
  $collateral_txhash \
  --fluxnode-privkey $fluxnode_privkey \
  --delegate-key $delegate_key \
  --rpc-user $rpc_user \
  --rpc-password $rpc_password \
  --dry-run
```

## Configuration

### Environment Variables

Create a `.env` file:

```bash
FLUX_RPC_HOST=127.0.0.1
FLUX_RPC_PORT=16124
FLUX_RPC_TIMEOUT=30
FLUX_OUTPUT_FORMAT=rich
```

See `examples/.env.example` for all options.

### RPC Authentication

The tool requires username/password authentication for all RPC connections.

**Get credentials from your flux.conf:**
```bash
grep rpcuser ~/.flux/flux.conf
grep rpcpassword ~/.flux/flux.conf
```

**Pass via CLI:**
```bash
flux-node-signer start <args> --rpc-user <user> --rpc-password <pass>
```

**Or use environment variables:**
```bash
export FLUX_RPC_USERNAME=myuser
export FLUX_RPC_PASSWORD=mypassword
flux-node-signer start <args> --rpc-user $FLUX_RPC_USERNAME --rpc-password $FLUX_RPC_PASSWORD
```

## Transaction Format

### Structure

```
Header (4 bytes)              # nVersion | (fOverwintered << 31)
├─ nType: int8_t (0x02)       # FLUXNODE_START_TX_TYPE
├─ nFluxTxVersion: int32_t    # 0x0101 (NORMAL | DELEGATES)
├─ collateralIn: COutPoint    # 36 bytes (hash + index)
│  ├─ hash: uint256           # 32 bytes, little-endian
│  └─ n: uint32_t             # 4 bytes, little-endian
├─ collateralPubkey: CPubKey  # Compact size + 33 bytes
├─ pubKey: CPubKey            # Fluxnode key, compact size + 33 bytes
├─ sigTime: uint32_t          # 4 bytes, little-endian
├─ fUsingDelegates: bool      # 1 byte (0x01)
├─ delegateData:              # CFluxnodeDelegates
│  ├─ nDelegateVersion: int8_t (0x01)
│  ├─ nType: int8_t (0x02)    # SIGNING type
│  └─ (no keys for SIGNING)
└─ sig: vector<unsigned char> # Compact size + 65 bytes
```

### Byte Order

- **All integers**: Little-endian
- **Transaction hash**: Reversed (little-endian)
- **Public keys**: No reversal

### Signing Process

1. Serialize transaction without signature
2. Compute transaction hash (double SHA256)
3. Build message: `"Zelcash Signed Message:\n" + tx_hash_hex`
4. Hash message with SHA256
5. Sign with secp256k1 recoverable signature (65 bytes)

## Development

### Running Tests

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov

# Run specific test file
uv run pytest tests/test_transaction.py

# Run specific test
uv run pytest tests/test_crypto.py::TestWIFDecoding::test_decode_mainnet_compressed
```

### Linting and Formatting

```bash
# Format code
uv run ruff format

# Lint code
uv run ruff check

# Type checking
uv run ty check
uv run pyright
```

### Project Structure

```
flux-node-signer/
├── src/
│   └── flux_delegate_starter/
│       ├── __init__.py          # Package exports
│       ├── __main__.py          # CLI interface
│       ├── transaction.py       # Transaction building
│       ├── crypto.py            # Cryptographic operations
│       ├── rpc_client.py        # RPC client
│       ├── models.py            # Pydantic models
│       ├── config.py            # Configuration
│       └── exceptions.py        # Custom exceptions
├── tests/
│   ├── test_transaction.py     # Transaction tests
│   ├── test_crypto.py           # Crypto tests
│   └── test_rpc_client.py      # RPC tests
├── examples/
│   ├── .env.example            # Environment config
│   ├── config.example.toml     # TOML config
│   └── collaterals.example.yaml # Batch file example
├── pyproject.toml              # Project config
└── README.md                   # This file
```

## Library Usage

You can also use the library programmatically in your Python code:

```python
import asyncio
from flux_delegate_starter import (
    FluxnodeStartTransaction,
    FluxRPCClient,
    FluxAPIClient,
    decode_wif,
)

async def main():
    # Decode delegate key
    delegate_privkey, _ = decode_wif("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn")

    # Build transaction
    tx = FluxnodeStartTransaction(
        collateral_txhash="1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d0",
        collateral_index=0,
        fluxnode_pubkey=bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
    )

    # Sign transaction
    tx.sign(delegate_privkey)

    # Option 1: Send via public API (default, no credentials needed)
    api_client = FluxAPIClient()
    txid = await api_client.send_raw_transaction(tx.to_hex())
    print(f"Transaction sent via API: {txid}")

    # Option 2: Send via direct RPC (requires credentials)
    rpc_client = FluxRPCClient(
        host="127.0.0.1",
        port=16124,
        username="myuser",
        password="mypassword"
    )
    txid = await rpc_client.send_raw_transaction(tx.to_hex())
    print(f"Transaction sent via RPC: {txid}")

if __name__ == "__main__":
    asyncio.run(main())
```

## Troubleshooting

### "RPC authentication required"

You must provide RPC credentials. Get them from your flux.conf:

```bash
grep rpcuser ~/.flux/flux.conf
grep rpcpassword ~/.flux/flux.conf
```

Then use:
```bash
flux-node-signer start <args> --rpc-user <user> --rpc-password <pass>
```

### "TX decode failed"

This usually means:
- Incorrect byte order (transaction hash must be reversed)
- Invalid public key format (must be compressed, 33 bytes)
- Incorrect serialization

Use `--decode --dry-run` to debug:

```bash
flux-node-signer start <args> --decode --dry-run
```

### "bad-txns-in-belowout"

The collateral transaction output doesn't exist or is already spent.

Verify with:

```bash
flux-cli getrawtransaction <txhash> 1
```

### "Invalid signature"

Check:
- Delegate key is correct WIF format
- Public keys match the delegate key
- Transaction is signed before sending

## Security Considerations

### Private Key Handling

- Never commit private keys to version control
- Use `.env` files (add to `.gitignore`)
- Consider using encrypted storage
- Rotate keys periodically

### RPC Security

- Use RPC over localhost when possible
- Enable RPC authentication
- Use TLS for remote connections
- Firewall RPC port

### Transaction Validation

- Always verify transaction details before signing
- Use `--dry-run` and `--decode` for testing
- Double-check collateral amounts
- Verify fluxnode public keys

## Examples

See the `examples/` directory for:
- `.env.example` - Environment configuration
- `config.example.toml` - TOML configuration
- `collaterals.example.yaml` - Batch file format

## License

MIT License - see [LICENSE](LICENSE) file for details

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Ensure all tests pass
5. Submit a pull request

## Support

- GitHub Issues: https://github.com/RunOnFlux/flux-node-signer/issues
- PyPI: https://pypi.org/project/flux-node-signer/

## Acknowledgments

- Built for the Flux ecosystem
- Uses secp256k1 cryptography via coincurve
- Transaction format follows Bitcoin-style serialization
- Inspired by fluxd's activefluxnode implementation
