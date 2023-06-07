use super::{account::AccountIdVar, ledger::AmountVar};

/// Transaction transferring some amount from one account to another.
pub struct TransactionVar {
    /// The account information of the sender.
    pub sender: AccountIdVar,
    /// The account information of the recipient.
    pub recipient: AccountIdVar,
    /// The amount being transferred from the sender to the receiver.
    pub amount: AmountVar,
    // Missing implementation
    // pub signature: <SigVerifyGadget<>>::SignatureVar;
}

// IMPORTANT NOTE: I am stuck here, where struct SignatureVar is missing in the library
// ark-crypto-primitive. I feel that this library is not good choice for
// ongoing development, it may be impact by missing implementation, and
// lack of ongoing support.
// Still, I am happy that I learn a lot throughout the coding days.
