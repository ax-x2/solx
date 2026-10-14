# solx

Solana wallet CLI for managing keys, accounts, transactions, and an encrypted vault from the terminal.

## Build

Requires Rust 1.89 or newer.

```sh
cargo build --release --locked
```

Linux and macOS are supported. CI runs on Linux and macOS 15 on Intel and Apple Silicon. Older macOS versions are untested.

## Quick start

Create the default wallet and vault:

```sh
# linux
sudo prlimit --pid "$$" --memlock=134217728:134217728
prlimit --pid "$$" --memlock

# macOS
sudo launchctl limit memlock 262144 262144


solx init main
```

The vault is written to `~/.solx/vault.enc`. Settings are stored inside the authenticated, encrypted vault. Keep the recovery phrase shown at creation.

Configure RPC, security, history, and aliases:

```sh
solx config
solx config show
```

Fresh vaults default to mainnet with no RPC endpoint. `config.example.toml` is a reference only.

Use another vault:

```sh
solx --vault /physical/path/vault.enc COMMAND
```

The vault directory must be owned by you and mode `700`. Files must be owner-only. Every path component is checked without following symlinks. On macOS, use physical paths such as `/private/tmp/...`, not `/tmp` or `/var`.

## Commands

```text
solx new NAME                      # new independent recovery phrase
solx new NAME --wallet SOURCE      # share SOURCE's phrase at its next unused index
solx import old --mnemonic         # hidden terminal prompt
solx import old --base58           # hidden terminal prompt
solx import old --keypair-file key.json
solx export NAME --private-key     # base58 64-byte keypair
solx export NAME --mnemonic        # recovery phrase and derivation path
solx list
solx list NAME
solx delete NAME
solx history --wallet NAME --limit 20
solx transfer --wallet NAME --to RECIPIENT --amount 0.25
solx transfer --wallet NAME --to RECIPIENT --amount ALL
solx token-transfer --wallet NAME --mint MINT --to RECIPIENT --amount 12.5
solx close-ata --wallet NAME MINT1 MINT2
solx close-ata --wallet NAME --all
solx close-ata --wallet NAME --burn MINT1
solx close-ata --wallet NAME --all --burn
```

`new NAME` creates a recovery phrase and its first account at `m/44'/501'/0'/0'`. `new NAME --wallet SOURCE` reuses SOURCE's phrase and advances that phrase's derivation index. The shared phrase is not printed again. Private-key-only imports cannot be used as a source. Creation is local and makes no RPC requests. The vault supports up to 32 stored masters and 128 wallet accounts.

Breaking change: `new` defaults to an independent recovery phrase. `--new-master` has been removed. Use `--wallet SOURCE` to share a phrase.

`import --base58` accepts a 32-byte seed or 64-byte keypair at a hidden prompt, including in the `solx>` shell. Inline secrets are rejected. Mnemonic import accepts ASCII English BIP39 words.

## Configuration

Run `solx config` or type `config` in the shell. Choose a group and field. Enter keeps a value, `on`/`off` toggles booleans, and `clear` unsets optional values. Changes remain in a draft until you review and type `SAVE`. `exit` discards the draft. The exact word `exit` is reserved, including at value prompts.

`rpc.show_balances` defaults to off. When off, `list` and `list NAME` show only saved names and addresses and make no network requests. When on, they fetch SOL and token balances from the configured endpoint. Listing never signs a transaction.

For local-only shell use, leave `History -> Fetch on startup` off and `History -> Refresh interval seconds` unset. These are the defaults. This is not a global offline mode. `history`, `transfer`, `token-transfer`, and `close-ata` still use RPC, and transaction commands can still sign.

The editor reuses an unlocked session or asks for the vault password once for the editing operation. Saving does not ask again. To avoid repeated prompts between shell commands, enable `Security -> Keep vault unlocked in shell`. Turning it off releases the cached key after saving. It is off by default.

An unchanged draft does not write the vault. Concurrent modifications cause a stale-edit error instead of overwriting another writer. Config editor input is never stored in shell history or a plaintext temporary file. The full RPC URL is visible during entry and in menus, reviews, and `config show`, including any path or query tokens.

`config` and `config show` display the number of committed settings changes and the last edit time from the local system clock. These fields are stored inside the same authenticated payload as the settings and cannot be edited through the menu. Invalid metadata, counter overflow, and a clock earlier than the previous edit are rejected. A save that completed its rename but failed directory synchronization counts as committed and is reported with uncertain durability.

This edit metadata is authenticated local metadata. It does not detect restoring an older valid vault, replacing the vault with a new one, or modifying the vault with the password/key. It is not rollback protection or an unforgeable audit trail.

## Exporting and deleting

`export NAME --private-key` shows the selected wallet's 64-byte keypair in base58.

`export NAME --mnemonic` reveals the recovery phrase and derivation path.

`solx delete NAME` removes the local wallet entry. Keep a backup if you need access later. Shared phrases cannot be erased. Imported private keys are removed with their wallet entry. Deleting the default wallet makes the first remaining wallet the default.

Derivation index history is tracked across stored copies of a phrase. Erasing every copy of a phrase or restoring an older vault loses newer history. A deleted source name cannot be selected.

## Security

The v5 vault uses AES-256-GCM-SIV with a 32-byte Argon2id v19 key: 64 MiB memory, 3 passes, 4 lanes, and a random 16-byte salt. All 48 header bytes, including KDF parameters, salt, and nonce, are authenticated. Unsupported costs are rejected before hashing. There is no automatic tuning or weaker fallback. Four lanes run sequentially; no worker pool is created.

This release requires v5. It cannot open v1-v4 vaults, and older releases cannot open v5. There is no migration reader. Keep recovery phrases, private keys, and old backups. `init` refuses to overwrite an existing vault.

Before creation or interactive password unlock, solx requires a 128 MiB locked-memory allowance. This is a process limit, not a 128 MiB allocation. Argon2 scratch is wiped and released immediately after derivation. If the soft limit is too low, solx raises its own soft limit to 128 MiB when the hard limit permits. Sufficient or unlimited soft limits remain unchanged. The hard limit is preserved. Check the launching shell with `ulimit -Sl` and `ulimit -Hl`.

A hard limit below 128 MiB cannot be raised by an ordinary user process. solx stops before asking for a password and reports that administrator access is required to configure the launching terminal or service. It never invokes sudo itself. Run solx as your normal user after setup.

Linux example:

```sh
# current process/shell
sudo prlimit --pid "$$" --memlock=134217728:134217728
prlimit --pid "$$" --memlock
solx init main

# permanent
echo -e "YOUR_USERNAME soft memlock 131072\nYOUR_USERNAME hard memlock 131072" | sudo tee /etc/security/limits.d/99-memlock.conf
# verify
ulimit -Sl
ulimit -Hl
```

MacOS example:
```sh
# current shell: set the maximum locked memory to 128 MiB
ulimit -S -l 262144

# verify current shell limits (macOS reports limits in 512-byte blocks)
ulimit -S -l
ulimit -H -l

# check the current process limits
launchctl limit

## permanent (launchd):

# set the locked-memory limit for the current launchd session
sudo launchctl limit memlock 262144 262144
```



Only the limit adjustment uses sudo. The adjustment lasts for that shell's lifetime. Raising an 8 MiB hard limit needs administrator permission; `ulimit` alone cannot raise it. If the host or container refuses the adjustment, its administrator must configure the launcher to grant the allowance.

Memory locking covers owned secret buffers, including password/input buffers, entropy, imported keys, mnemonic text and objects, derived seed/key owners, signing-key storage, vault plaintext/serialization buffers, and the Argon2 work area. Owners cannot reallocate. Dropping them erases the full mapping, including unused capacity and padding, before unlocking and unmapping. Any allocation, locking, or required protection failure stops the operation. There is no pageable fallback.

This is protection of identified owned storage, not full process memory locking. Function arguments/return values, stacks, registers, compiler-generated copies, and all internal BIP39/HMAC/digest/Ed25519 state are not covered. Explicit zeroization cannot prove erasure of every copy. Linux disables process dumpability and core dumps. macOS disables core dumps but does not provide the same debugger restrictions. These controls do not protect against a compromised OS or every hibernation/memory-capture mechanism.

Saves use a nonblocking writer lock, reject stale revisions, and write/sync a private temporary file before atomic rename. If directory synchronization fails after rename, solx reports that the vault was saved with uncertain durability. It does not retry automatically.

`vault.enc.lock` intentionally remains on disk. An active OS file lock marks a writer as busy and produces `vault is busy; retry`. Keep the file in place. Deleting it can let competing writers lock different files. It is unrelated to the locked-memory allowance used by Argon2id.

Shell key caching defaults to off. If explicitly enabled, `lock` clears the retained unlocking key. The shell keeps at most 64 commands in memory and never writes a history file.

## Checks

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Production-profile KDF/unlock tests and process/terminal tests run separately:

```sh
cargo test --locked -p solx -- --ignored --test-threads=1
```

These require sufficient locked-memory allowance. They fail if the required protection is unavailable. They do not skip it or weaken the production KDF. Repeat both suites with `--release` to exercise optimized erasure.

On a restricted host, run the isolated process-policy and low-memory tests with:

```sh
cargo test --locked -p solx -- --ignored --test-threads=1 \
  --skip production_vector \
  --skip wrong_password_and_tamper \
  --skip documented_init \
  --skip cancelled_invalid
```

All fixtures use synthetic secrets and local mock RPC servers.