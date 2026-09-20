# solx

a solana wallet cli for managing keys, accounts, transactions and an encrypted vault from the terminal.

commands are registered as built-in plugins; new commands can be added to the `PLUGINS` table. runtime-loaded plugins are intentionally unsupported in the signing process.


## quick start

`solx init main` creates the `main` wallet, `~/.solx/vault.enc`, and if absent, `~/.solx/config.toml` from [config.example.toml](config.example.toml).

keep the recovery phrase shown at creation.

```text
solx new NAME                      # next m/44'/501'/index'/0' account
solx new NAME --new-master        # independent recovery phrase
solx import old --mnemonic            # hidden terminal prompt
solx import old --base58              # hidden terminal prompt
solx import old --keypair-file key.json
solx list
solx list --wallet NAME
solx history --wallet NAME --limit 20
solx transfer --wallet NAME --to RECIPIENT --amount 0.25
solx transfer --wallet NAME --to RECIPIENT --amount ALL
solx token-transfer --wallet NAME --mint MINT --to RECIPIENT --amount 12.5
solx close-ata --wallet NAME MINT1 MINT2
solx close-ata --wallet NAME --all
solx close-ata --wallet NAME --burn MINT1
solx close-ata --wallet NAME --all --burn
```

inside the interactive `solx>` shell, `import NAME --base58 KEY` also accepts a 32-byte seed or 64-byte keypair encoded in base58.

## security 

the vault is versioned and authenticated with aes-256-gcm-siv and a scrypt-derived key. it stores wallet secrets and metadata; config contains no wallet secrets.

the shell cache the derived key in memory. lock clears it, while `cache_unlocked_in_shell = false` prompts for every command. vault contents are decrypted per command.

memory locking is best effort and cannot protect against a compromised process or host. the shell keeps the last 64 commands in memory and never writes a history file.