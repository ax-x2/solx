# Secret cleanup patches

This is a minimal source patch to the key derivation crate used by solx. Cargo.lock pins the remaining dependency graph. The patch does not change wallet derivation paths or algorithms. The vault password KDF uses registry Argon2id with caller-owned locked, zeroizing scratch.

| Package | Registry version | Original crates.io archive checksum |
| --- | --- | --- |
| ed25519-dalek-bip32 | 0.3.0 | `6b49a684b133c4980d7ee783936af771516011c8cd15f429dbda77245e282f03` |

Source: [ed25519-dalek-bip32](https://github.com/jpopesculian/ed25519-dalek-bip32). Original authors and licensing remain in the package manifest. The Apache-2.0 license text is included.

Changes:

- ed25519-dalek-bip32: wipe chain codes on drop, HMAC output after extracting key material, and explicit secret byte temporaries. Enable ed25519-dalek zeroize in the package itself. Redact ExtendedSigningKey Debug output, including its chain code.
- Add the zeroize dependency. Formatting follows the workspace formatter. The original upstream test vectors remain present and run with workspace tests.

Scope: these changes erase the identified owned buffers. They do not prove erasure of compiler-generated copies, registers, or all internal HMAC/digest state. solx separately locks its identified owned buffers through its local memory module; these dependency patches do not supply full process/stack memory locking.
