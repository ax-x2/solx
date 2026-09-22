use ed25519_dalek::{Signer as _, SigningKey};
use solana_pubkey::Pubkey;
use solana_transaction::Signature;
use zeroize::Zeroizing;

/// the wallet only needs an Ed25519 keypair, not the sdks other signer types.
pub struct Keypair(SigningKey);

impl Keypair {
    pub fn new_from_array(secret: [u8; 32]) -> Self {
        let secret = Zeroizing::new(secret);
        Self(SigningKey::from_bytes(&secret))
    }

    pub fn pubkey(&self) -> Pubkey {
        Pubkey::from(self.0.verifying_key().to_bytes())
    }

    pub fn to_keypair_bytes(&self) -> Zeroizing<[u8; 64]> {
        Zeroizing::new(self.0.to_keypair_bytes())
    }

    pub fn sign_message(&self, message: &[u8]) -> Signature {
        Signature::from(self.0.sign(message).to_bytes())
    }
}

impl TryFrom<&[u8]> for Keypair {
    type Error = &'static str;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes: &[u8; 64] = bytes.try_into().map_err(|_| "invalid keypair length")?;
        SigningKey::from_keypair_bytes(bytes)
            .map(Self)
            .map_err(|_| "keypair public key does not match its secret key")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
