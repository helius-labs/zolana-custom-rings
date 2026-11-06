use solana_address::Address;
use solana_message::VersionedMessage;
use solana_signature::Signature;
use solana_signer::{PresignerError, Signer, SignerError};
use solana_transaction::versioned::VersionedTransaction;
use spr_client::sign_transaction;

use crate::error::RingRpcError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CollectedSignature {
    pub signer: Address,
    pub signature: Signature,
}

/// A collected signature, refused unless it signs the message.
struct Presigned(CollectedSignature);

/// Refused unless `signatures` sign `message` for every signer it names.
pub(crate) fn presigned_transaction(
    message: &VersionedMessage,
    signatures: &[CollectedSignature],
) -> Result<VersionedTransaction, RingRpcError> {
    let presigned: Vec<Presigned> = signatures.iter().copied().map(Presigned).collect();
    let signers: Vec<&dyn Signer> = presigned
        .iter()
        .map(|signer| signer as &dyn Signer)
        .collect();
    Ok(sign_transaction(message.clone(), &signers)?)
}

impl Signer for Presigned {
    fn try_pubkey(&self) -> Result<Address, SignerError> {
        Ok(self.0.signer)
    }

    fn try_sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        match self.0.signature.verify(self.0.signer.as_ref(), message) {
            true => Ok(self.0.signature),
            false => Err(PresignerError::VerificationFailure.into()),
        }
    }

    fn is_interactive(&self) -> bool {
        false
    }
}
