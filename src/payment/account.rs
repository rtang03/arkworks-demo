use ark_crypto_primitives::signature::schnorr::{PublicKey, SecretKey};
use ark_ed_on_bls12_381::EdwardsProjective as JubJub;
use ark_serialize::CanonicalSerialize;

use super::ledger::*;

/// Account public key used to verify transaction signatures.
pub type AccountPublicKey = PublicKey<JubJub>;

/// Account secret key used to create transaction signatures.
pub type AccountSecretKey = SecretKey<JubJub>;

#[derive(Hash, Eq, PartialEq, Copy, Clone, Ord, PartialOrd, Debug)]
pub struct AccountId(pub u8);

impl AccountId {
    pub fn to_bytes_le(&self) -> Vec<u8> {
        vec![self.0]
    }

    /// Increment the identifier in place.
    pub fn checked_increment(&mut self) -> Option<()> {
        self.0.checked_add(1).map(|result| self.0 = result)
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Copy, Clone, CanonicalSerialize)]
pub struct AccountInformation {
    pub public_key: AccountPublicKey,
    pub balance: Amount,
}

// impl AccountInformation {
//     /// Convert the account information to bytes.
//     pub fn to_bytes_le(&self, uncompressed_bytes:&Vec<u8>) -> Vec<u8> {
//         let mut uncompressed_bytes = Vec::new();
//         &self.serialize_uncompressed(&mut uncompressed_bytes);
//         uncompressed_bytes.as_slice()
//     }
// }
