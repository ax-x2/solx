//! The only accepted vault KDF profile. Password hashing is unlock-time work.
use crate::{
    Result, fail,
    secret::{LockedBlocks, LockedKey},
};
use argon2::{Algorithm, Argon2, Params, Version};

pub const KDF_ID: u8 = 1;
pub const ARGON2_VERSION: u8 = 0x13;
pub const MAX_PASSWORD_BYTES: usize = 1024;
// Startup allowance, including headroom beyond the 64 MiB Argon2 workspace.
const MEMLOCK_ALLOWANCE: libc::rlim_t = 128 * 1024 * 1024;

/// Prepare this process's soft allowance before interactive input, within its
/// existing hard limit. This neither reserves memory nor replaces actual mlock.
pub fn prepare_memlock_allowance() -> Result<()> {
    ensure_memlock_allowance(MEMLOCK_ALLOWANCE)
}

fn ensure_memlock_allowance(required: libc::rlim_t) -> Result<()> {
    let mut limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit initializes a live output; this never changes OS limits.
    if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limits) } != 0 {
        return Err(format!(
            "cannot read the locked-memory allowance: {}",
            std::io::Error::last_os_error()
        )
        .into());
    }
    if limits.rlim_cur == libc::RLIM_INFINITY || limits.rlim_cur >= required {
        return Ok(());
    }
    if limits.rlim_max != libc::RLIM_INFINITY && limits.rlim_max < required {
        return Err(format!(
            "insufficient locked-memory allowance: soft={} bytes, hard={} bytes; \
             solx requires {} MiB. Administrator access is required to increase \
             the hard limit for the launching terminal or service. Run solx as \
             your normal user after setup (see README.md)",
            limits.rlim_cur,
            limits.rlim_max,
            required / (1024 * 1024),
        )
        .into());
    }
    let raised = libc::rlimit {
        rlim_cur: required,
        rlim_max: limits.rlim_max,
    };
    // SAFETY: live input; adjusts only this process's soft limit and preserves
    // the hard limit. No privilege elevation or parent/host policy changes.
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &raised) } != 0 {
        return Err(format!(
            "cannot raise this process's locked-memory soft limit from {} to \
             {required} bytes: {}. Ask your administrator to configure the \
             launching terminal or service; run solx as your normal user (see README.md)",
            limits.rlim_cur,
            std::io::Error::last_os_error(),
        )
        .into());
    }
    Ok(())
}

/// Private fields ensure only a validated, bounded profile reaches derivation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2idParams {
    memory_kib: u32,
    passes: u32,
    lanes: u32,
}

impl Argon2idParams {
    // RFC 9106's second recommended profile, with a 32-byte output.
    pub const VAULT: Self = Self {
        memory_kib: 65536,
        passes: 3,
        lanes: 4,
    };

    pub fn from_costs(memory_kib: u32, passes: u32, lanes: u32) -> Result<Self> {
        let params = Self {
            memory_kib,
            passes,
            lanes,
        };
        if params != Self::VAULT {
            return fail("unsupported Argon2id profile (expected 65536 KiB, 3 passes, 4 lanes)");
        }
        Ok(params)
    }

    pub fn costs(self) -> [u32; 3] {
        [self.memory_kib, self.passes, self.lanes]
    }

    pub fn derive(self, password: &str, salt: &[u8; 16]) -> Result<LockedKey> {
        if password.is_empty() || password.len() > MAX_PASSWORD_BYTES {
            return fail("password must be 1..=1024 bytes");
        }
        let params = Params::new(self.memory_kib, self.passes, self.lanes, Some(32))
            .map_err(|_| "invalid Argon2id parameters")?;
        let mut key = LockedKey::new()?;
        let mut scratch = allocate_scratch(params.block_count())?;
        #[cfg(test)]
        scratch.watch();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        argon2
            .hash_password_into_with_memory(
                password.as_bytes(),
                salt,
                key.bytes_mut(),
                &mut *scratch,
            )
            .map_err(|_| "Argon2id derivation failed")?;
        #[cfg(test)]
        crate::test_support::fail_at(crate::test_support::Fault::AfterHash)?;
        // LockedBlocks wipes the complete mapping before releasing its lock.
        Ok(key)
    }
}

fn allocate_scratch(blocks: usize) -> Result<LockedBlocks> {
    #[cfg(test)]
    crate::test_support::fail_at(crate::test_support::Fault::Allocate)?;
    LockedBlocks::new(blocks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "isolated resource-limit subprocesses; run with --ignored --test-threads=1"]
    fn soft_memlock_limit_changes_are_isolated() {
        fn limits() -> libc::rlimit {
            let mut value = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: live output, no process policy mutation.
            assert_eq!(
                unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut value) },
                0
            );
            value
        }

        const MIB: libc::rlim_t = 1024 * 1024;
        if let Ok(mode) = std::env::var("SOLX_MEMLOCK_LIMIT_TEST_CHILD") {
            // Only this disposable child is changed. Small allowances exercise
            // real OS policy on restricted hosts without changing the KDF.
            let initial = libc::rlimit {
                rlim_cur: match mode.as_str() {
                    "raise" | "boundary" => 0,
                    "sufficient" => 2 * MIB,
                    "denied" | "production" => MIB,
                    _ => panic!("unknown child test mode"),
                },
                rlim_max: if mode == "boundary" { MIB } else { 2 * MIB },
            };
            // SAFETY: live input; changes only the isolated child.
            assert_eq!(
                unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &initial) },
                0
            );
            let expected_soft = match mode.as_str() {
                "raise" | "boundary" => {
                    assert!(LockedKey::new().is_err());
                    ensure_memlock_allowance(MIB).unwrap();
                    // The raised allowance really permits locked allocation.
                    assert!(LockedKey::new().is_ok());
                    ensure_memlock_allowance(MIB).unwrap();
                    MIB
                }
                "sufficient" => {
                    ensure_memlock_allowance(MIB).unwrap();
                    initial.rlim_cur
                }
                "denied" | "production" => {
                    let result = if mode == "production" {
                        prepare_memlock_allowance()
                    } else {
                        ensure_memlock_allowance(3 * MIB)
                    };
                    let error = result.unwrap_err().to_string();
                    assert!(
                        error.contains("Administrator access is required"),
                        "{error}"
                    );
                    assert!(error.contains("normal user"), "{error}");
                    if mode == "production" {
                        assert!(error.contains("128 MiB"), "{error}");
                    }
                    initial.rlim_cur
                }
                _ => unreachable!(),
            };
            let after = limits();
            assert_eq!(after.rlim_cur, expected_soft);
            assert_eq!(after.rlim_max, initial.rlim_max);
            return;
        }

        let before = limits();
        for mode in ["raise", "boundary", "sufficient", "denied", "production"] {
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "kdf::tests::soft_memlock_limit_changes_are_isolated",
                    "--test-threads=1",
                ])
                .env("SOLX_MEMLOCK_LIMIT_TEST_CHILD", mode)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{mode}: {}{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
        }
        let after = limits();
        assert_eq!(after.rlim_cur, before.rlim_cur);
        assert_eq!(after.rlim_max, before.rlim_max);
    }

    #[test]
    #[ignore = "requires >64 MiB memlock allowance; run serially with --ignored"]
    fn production_vector_and_scratch_erasure_on_success_and_failure() {
        // Independently generated with reference libargon2 argon2id_hash_raw:
        // t=3, m=65536, p=4, version=19, output=32, no secret/associated data.
        let key = Argon2idParams::VAULT
            .derive("solx Argon2id test password", b"0123456789abcdef")
            .unwrap();
        assert_eq!(
            key.bytes(),
            &[
                0xe3, 0x29, 0xf1, 0x48, 0x8f, 0x49, 0xe4, 0xee, 0x83, 0xd9, 0xae, 0xfe, 0xc4, 0x7a,
                0x32, 0xad, 0xc8, 0x0d, 0x10, 0x60, 0x64, 0xdb, 0x7f, 0xdb, 0xf1, 0xca, 0x78, 0x4b,
                0x35, 0x74, 0x9c, 0x58,
            ]
        );
        assert_eq!(crate::secret::was_erased(), Some(true));
        for point in [
            crate::test_support::Fault::Allocate,
            crate::test_support::Fault::AfterHash,
        ] {
            let result = crate::test_support::with_fault(point, || {
                Argon2idParams::VAULT.derive("test password", &[2; 16])
            });
            assert!(result.is_err());
            assert_eq!(
                crate::secret::was_erased(),
                if point == crate::test_support::Fault::AfterHash {
                    Some(true)
                } else {
                    None
                }
            );
        }
    }

    #[test]
    fn rejects_unbounded_costs_passwords_and_allocation_failure() {
        for costs in [
            [0, 3, 4],
            [65536, 0, 4],
            [65536, 3, 0],
            [u32::MAX, 3, 4],
            [65536, u32::MAX, 4],
            [65536, 3, u32::MAX],
            [32768, 3, 4],
        ] {
            assert!(Argon2idParams::from_costs(costs[0], costs[1], costs[2]).is_err());
        }
        assert!(Argon2idParams::VAULT.derive("", &[0; 16]).is_err());
        assert!(
            Argon2idParams::VAULT
                .derive(&"x".repeat(1025), &[0; 16])
                .is_err()
        );
        assert!(allocate_scratch(usize::MAX).is_err());
    }

    #[test]
    fn rfc_9106_argon2id_vector() {
        // https://www.rfc-editor.org/rfc/rfc9106.html#section-5.3
        let mut builder = argon2::ParamsBuilder::new();
        builder
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .output_len(32)
            .data(argon2::AssociatedData::new(&[4; 12]).unwrap());
        let params = builder.build().unwrap();
        let mut scratch = allocate_scratch(params.block_count()).unwrap();
        let argon2 =
            Argon2::new_with_secret(&[3; 8], Algorithm::Argon2id, Version::V0x13, params).unwrap();
        let mut output = LockedKey::new().unwrap();
        scratch.watch();
        argon2
            .hash_password_into_with_memory(&[1; 32], &[2; 16], output.bytes_mut(), &mut *scratch)
            .unwrap();
        assert_eq!(
            *output,
            [
                0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b,
                0x53, 0xc9, 0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9,
                0x6b, 0x01, 0xe6, 0x59,
            ]
        );
        assert!(scratch.iter().any(|b| b.as_ref().iter().any(|v| *v != 0)));
        drop(scratch);
        assert_eq!(crate::secret::was_erased(), Some(true));
    }
}
