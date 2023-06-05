use super::{
    account::{AccountId, AccountInformation, AccountPublicKey, AccountSecretKey},
    transaction::Transaction,
};
use crate::basic_merkle_tree::common::{CompressH, JubJubMerkleTree, LeafH, SimplePath};
use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::MerkleTree,
    signature::{
        schnorr::{self, PublicKey, Schnorr},
        SignatureScheme,
    },
};
use ark_ed_on_bls12_381::EdwardsProjective as JubJub;
use ark_serialize::CanonicalSerialize;
use ark_std::{log2, rand::Rng};
use blake2::Blake2s256 as Blake2s;
use std::collections::HashMap;

/// Represents transaction amounts and account balances.
#[derive(Hash, Eq, PartialEq, Copy, Clone, PartialOrd, Ord, Debug, CanonicalSerialize)]
pub struct Amount(pub u64);

impl Amount {
    pub fn to_bytes_le(&self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }

    pub fn checked_add(self, other: Self) -> Option<Self> {
        self.0.checked_add(other.0).map(Self) // shorthand for map(|a| Self(a))
    }

    pub fn checked_sub(self, other: Self) -> Option<Self> {
        self.0.checked_sub(other.0).map(Self)
    }
}

pub type SignatureParameters = schnorr::Parameters<JubJub, Blake2s>;

/// The parameters that are used in transaction creation and validation.
#[derive(Clone)]
pub struct Parameters {
    pub sig_params: SignatureParameters,
    pub leaf_crh_params: <LeafH as CRHScheme>::Parameters,
    pub two_to_one_crh_params: <CompressH as TwoToOneCRHScheme>::Parameters,
}

impl Parameters {
    pub fn sample<R: Rng>(rng: &mut R) -> Self {
        let sig_params = <Schnorr<JubJub, Blake2s> as SignatureScheme>::setup(rng).unwrap();
        let leaf_crh_params = <LeafH as CRHScheme>::setup(rng).unwrap();
        let two_to_one_crh_params = <CompressH as TwoToOneCRHScheme>::setup(rng).unwrap();
        Self {
            sig_params,
            leaf_crh_params,
            two_to_one_crh_params,
        }
    }
}

/// A Merkle tree containing account information.
pub type AccMerkleTree = JubJubMerkleTree;
pub type AccRoot = <CompressH as TwoToOneCRHScheme>::Output;
pub type AccPath = SimplePath;

#[derive(Clone)]
pub struct State {
    /// What is the next available account identifier?
    pub next_available_account: Option<AccountId>,
    /// A merkle tree mapping where the i-th leaf corresponds to the i-th account's
    /// information (= balance and public key).
    pub account_merkle_tree: AccMerkleTree,
    /// A mapping from an account's identifier to its information (= balance and public key).
    pub id_to_account_info: HashMap<AccountId, AccountInformation>,
    /// A mapping from a public key to an account's identifier.
    pub pub_key_to_id: HashMap<PublicKey<JubJub>, AccountId>,
}

impl State {
    /// Create an empty ledger that supports `num_accounts` accounts.
    pub fn new(num_accounts: usize, parameters: &Parameters) -> Self {
        let height = log2(num_accounts);
        let account_merkle_tree: AccMerkleTree = MerkleTree::blank(
            &parameters.leaf_crh_params,
            &parameters.two_to_one_crh_params,
            height as usize,
        )
        .unwrap();
        let pub_key_to_id = HashMap::with_capacity(num_accounts);
        let id_to_account_info = HashMap::with_capacity(num_accounts);
        Self {
            next_available_account: Some(AccountId(1)),
            account_merkle_tree,
            pub_key_to_id,
            id_to_account_info,
        }
    }

    /// Return the root of the account Merkle tree.
    pub fn root(&self) -> AccRoot {
        self.account_merkle_tree.root()
    }

    /// Create a new account with public key `pub_key`. Returns a fresh account identifier
    /// if there is space for a new account, and returns `None` otherwise.
    /// The initial balance of the new account is 0.
    pub fn register(&mut self, public_key: AccountPublicKey) -> Option<AccountId> {
        self.next_available_account.and_then(|id| {
            // Construct account information for the new account.
            let account_info = AccountInformation {
                public_key,
                balance: Amount(0),
            };
            // Insert information into the relevant accounts.
            self.pub_key_to_id.insert(public_key, id);
            let mut uncompressed_bytes = Vec::new();
            // todo: revisit unwrap()
            account_info
                .serialize_uncompressed(&mut uncompressed_bytes)
                .unwrap();
            self.account_merkle_tree
                .update(id.0 as usize, uncompressed_bytes.as_slice())
                .expect("should exist");
            self.id_to_account_info.insert(id, account_info);
            // Increment the next account identifier.
            self.next_available_account
                .as_mut()
                .and_then(|cur| cur.checked_increment());
            Some(id)
        })
    }

    /// Samples keys and registers these in the ledger.
    pub fn sample_keys_and_register<R: Rng>(
        &mut self,
        ledger_params: &Parameters,
        rng: &mut R,
    ) -> Option<(AccountId, AccountPublicKey, AccountSecretKey)> {
        let (pub_key, secret_key) =
            <Schnorr<JubJub, Blake2s> as SignatureScheme>::keygen(&ledger_params.sig_params, rng)
                .unwrap();
        self.register(pub_key).map(|id| (id, pub_key, secret_key))
    }

    /// Update the balance of `id` to `new_amount`.
    /// Returns `Some(())` if an account with identifier `id` exists already, and `None`
    /// otherwise.
    pub fn update_balance(&mut self, id: AccountId, new_amount: Amount) -> Option<()> {
        let tree = &mut self.account_merkle_tree;
        self.id_to_account_info
            .get_mut(&id)
            .map(|account_info: &mut AccountInformation| {
                account_info.balance = new_amount;
                let mut uncompressed_bytes = Vec::new();
                // todo: revisit unwrap()
                account_info
                    .serialize_uncompressed(&mut uncompressed_bytes)
                    .unwrap();
                tree.update(id.0 as usize, uncompressed_bytes.as_slice())
                    .expect("should exist")
            })
    }

    /// Update the state by applying the transaction `tx`, if `tx` is valid.
    pub fn apply_transaction(&mut self, pp: &Parameters, tx: &Transaction) -> Option<()> {
        if tx.validate(pp, self) {
            let old_sender_bal = self.id_to_account_info.get(&tx.sender)?.balance;
            let old_receiver_bal = self.id_to_account_info.get(&tx.recipient)?.balance;
            let new_sender_bal = old_sender_bal.checked_sub(tx.amount)?;
            let new_receiver_bal = old_receiver_bal.checked_add(tx.amount)?;
            self.update_balance(tx.sender, new_sender_bal);
            self.update_balance(tx.recipient, new_receiver_bal);
            Some(())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use super::super::transaction::Transaction;
    use super::{AccountId, Amount, Parameters, State};

    #[test]
    fn end_to_end() {
        let mut rng = ark_std::test_rng();
        let pp = Parameters::sample(&mut rng);
        let mut state = State::new(32, &pp);
        // Let's make an account for Alice.
        let (alice_id, _alice_pk, alice_sk) =
            state.sample_keys_and_register(&pp, &mut rng).unwrap();
        // Let's give her some initial balance to start with.
        state
            .update_balance(alice_id, Amount(10))
            .expect("Alice's account should exist");
        // Let's make an account for Bob.
        let (bob_id, _bob_pk, bob_sk) = state.sample_keys_and_register(&pp, &mut rng).unwrap();

        // Alice wants to transfer 5 units to Bob.
        let tx1 = Transaction::create(&pp, alice_id, bob_id, Amount(5), &alice_sk, &mut rng);
        assert!(tx1.validate(&pp, &state));
        state.apply_transaction(&pp, &tx1).expect("should work");
        // Let's try creating invalid transactions:
        // First, let's try a transaction where the amount is larger than Alice's balance.
        let bad_tx = Transaction::create(&pp, alice_id, bob_id, Amount(6), &alice_sk, &mut rng);
        assert!(!bad_tx.validate(&pp, &state));
        assert!(matches!(state.apply_transaction(&pp, &bad_tx), None));
        // Next, let's try a transaction where the signature is incorrect:
        let bad_tx = Transaction::create(&pp, alice_id, bob_id, Amount(5), &bob_sk, &mut rng);
        assert!(!bad_tx.validate(&pp, &state));
        assert!(matches!(state.apply_transaction(&pp, &bad_tx), None));

        // Finally, let's try a transaction to an non-existant account:
        let bad_tx =
            Transaction::create(&pp, alice_id, AccountId(10), Amount(5), &alice_sk, &mut rng);
        assert!(!bad_tx.validate(&pp, &state));
        assert!(matches!(state.apply_transaction(&pp, &bad_tx), None));
    }
}
