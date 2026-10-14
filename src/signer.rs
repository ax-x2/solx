use crate::{
    Result,
    secret::{Locked, LockedKeypair},
};
use ed25519_dalek::{Signer as _, SigningKey};
use solana_pubkey::Pubkey;
use solana_transaction::Signature;

/// the wallet only needs an Ed25519 keypair, not the sdks other signer types.
pub struct Keypair(Locked<SigningKey>);

impl Keypair {
    #[cfg(test)]
    pub fn new_from_array(secret: [u8; 32]) -> Self {
        Self::from_seed_bytes(&secret).unwrap()
    }
    pub fn from_seed_bytes(secret: &[u8; 32]) -> Result<Self> {
        Ok(Self(Locked::try_new(|| {
            Ok(SigningKey::from_bytes(secret))
        })?))
    }

    pub fn pubkey(&self) -> Pubkey {
        Pubkey::from(self.0.verifying_key().to_bytes())
    }

    pub fn to_keypair_bytes(&self) -> Result<LockedKeypair> {
        let mut bytes = LockedKeypair::new()?;
        bytes[..32].copy_from_slice(self.0.as_bytes());
        bytes[32..].copy_from_slice(self.0.verifying_key().as_bytes());
        Ok(bytes)
    }

    pub fn sign_message(&self, message: &[u8]) -> Signature {
        Signature::from(self.0.sign(message).to_bytes())
    }
}

impl TryFrom<&[u8]> for Keypair {
    type Error = Box<dyn std::error::Error>;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let bytes: &[u8; 64] = bytes.try_into().map_err(|_| "invalid keypair length")?;
        Ok(Self(Locked::try_new(|| {
            SigningKey::from_keypair_bytes(bytes)
                .map_err(|_| "keypair public key does not match its secret key".into())
        })?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_signing_does_not_allocate() {
        use ed25519_dalek::Verifier as _;
        let key = Keypair::new_from_array([7; 32]);
        let message = [42; 512];
        let _ = key.sign_message(&message); // Warm CPU feature detection.
        let (signature, allocations) =
            crate::test_alloc::allocations_during(|| key.sign_message(&message));
        assert_eq!(allocations, 0);
        key.0
            .verifying_key()
            .verify(
                &message,
                &ed25519_dalek::Signature::from_bytes(signature.as_array()),
            )
            .unwrap();
    }

    #[test]
    fn imported_keypair_requires_matching_public_key() {
        let bytes = SigningKey::from_bytes(&[7; 32]).to_keypair_bytes();
        assert_eq!(
            Keypair::try_from(&bytes[..]).unwrap().pubkey().as_array(),
            &bytes[32..]
        );
        let mut corrupt = bytes;
        corrupt[32] ^= 1;
        assert!(Keypair::try_from(&corrupt[..]).is_err());
    }
}
