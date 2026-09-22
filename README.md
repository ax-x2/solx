# solx

WIP. testing.

a solana wallet cli for managing keys, accounts, transactions and an encrypted vault from the terminal.

## quick start

`solx init main` creates the `main` wallet, `~/.solx/vault.enc`, and if absent, `~/.solx/config.toml` from [config.example.toml](config.example.toml).

keep the recovery phrase shown at creation.

```text
solx new NAME                      # next m/44'/501'/index'/0' account
solx new NAME --new-master        # independent recovery phrase
solx import old --mnemonic            # hidden terminal prompt
solx import old --base58              # hidden terminal prompt
solx import old --keypair-file key.json
solx export NAME --private-key      # reveal a base58 64-byte keypair
solx export NAME --mnemonic         # reveal recovery phrase and derivation path
solx list
solx list --wallet NAME
solx delete NAME                    # delete a local wallet
solx history --wallet NAME --limit 20
solx transfer --wallet NAME --to RECIPIENT --amount 0.25
solx transfer --wallet NAME --to RECIPIENT --amount ALL
solx token-transfer --wallet NAME --mint MINT --to RECIPIENT --amount 12.5
solx close-ata --wallet NAME MINT1 MINT2
solx close-ata --wallet NAME --all      # all with zero amounts
solx close-ata --wallet NAME --burn MINT1
solx close-ata --wallet NAME --all --burn # burn and claim rent
```

inside the interactive `solx>` shell, `import NAME --base58 KEY` also accepts a 32-byte seed or 64-byte keypair encoded in base58.

## exporting a wallet

`export NAME --private-key` shows the selected wallets 64-byte keypair in base58.

## deleting a wallet

`solx delete NAME` removes the local wallet entry; keep a backup if you need access later.

shared phrases cannot be erased. imported private keys are removed with their wallet entry.

deleting the default wallet makes the first remaining wallet the default. `new NAME` uses the first retained recovery phrase and never reuses its deleted derivation indices.

## security

the vault is versioned and authenticated with aes-256-gcm-siv and a scrypt-derived key. it stores wallet secrets and metadata; config contains no wallet secrets.

memory locking is best effort and cannot protect against a compromised process or host. the shell keeps the last 64 commands in memory and never writes a history file.
