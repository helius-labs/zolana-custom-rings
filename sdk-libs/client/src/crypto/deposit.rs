//! Deposits publish asset, amount and ring in the clear, only the blinding and memo stay sealed.

use borsh::BorshDeserialize;
use solana_address::Address;
use spr_event::{EncryptedRingDepositOutput, OutputDataEncoding, ENCRYPTED_RING_DEPOSIT_SCHEME};
use spr_event_parser::decode_encrypted_ring_deposit_output_data;
use spr_keypair::{ShieldedAddress, X25519Pubkey};
use spr_transaction::{
    AssetRegistry, DecryptLabel, DecryptRequest, DepositPayload, ShieldedKeys, ShieldedTransaction,
    TransactionError, WalletUtxo,
};
use zeroize::Zeroizing;
use zolana_ring_transaction::{is_contributory, RingDepositPlaintext};

use crate::{exactly_one, AnonymousError};

/// One deposit slot of a transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingDeposit {
    /// The note's owner tag, the account the value was shielded for.
    pub depositor: [u8; 32],
    pub asset: Address,
    pub amount: u64,
}

/// The deposits of `ring` in one indexed transaction, in slot order.
pub fn ring_deposits_in(
    slots: impl IntoIterator<Item = ([u8; 32], Vec<u8>)>,
    ring: Address,
) -> Vec<RingDeposit> {
    slots
        .into_iter()
        .filter_map(|(view_tag, payload)| deposit_of(&view_tag, &payload, ring))
        .collect()
}

fn deposit_of(view_tag: &[u8; 32], payload: &[u8], ring: Address) -> Option<RingDeposit> {
    let OutputDataEncoding::Encrypted(blob) = OutputDataEncoding::try_from_slice(payload).ok()?
    else {
        return None;
    };
    let (&ENCRYPTED_RING_DEPOSIT_SCHEME, body) = blob.split_first()? else {
        return None;
    };
    let output = EncryptedRingDepositOutput::try_from_slice(body).ok()?;
    (output.ring_program_id == ring.to_bytes()).then(|| RingDeposit {
        depositor: *view_tag,
        asset: Address::new_from_array(output.asset),
        amount: output.amount,
    })
}

pub(crate) struct DepositOpener<'a, K: ?Sized> {
    pub keys: &'a K,
    pub address: &'a ShieldedAddress,
    pub assets: &'a AssetRegistry,
    pub deposit_payload: DepositPayload,
}

pub(crate) struct DepositSlot<'a> {
    pub deposit: &'a ShieldedTransaction,
    pub position: usize,
    pub viewing_pubkey: X25519Pubkey,
}

pub(crate) enum OpenedDeposit {
    Note(Box<WalletUtxo>),
    UnknownMint(Address),
}

impl<K: ShieldedKeys + ?Sized> DepositOpener<'_, K> {
    /// Deposits of any ring among `transactions` under a held viewing key's tag, nullifiers unset.
    pub(crate) fn open_held(
        &self,
        transactions: &[ShieldedTransaction],
    ) -> Result<Vec<OpenedDeposit>, AnonymousError> {
        let held = self.keys.viewing_public_keys();
        let mut opened = Vec::new();
        for deposit in transactions {
            for (position, slot) in deposit.output_slots.iter().enumerate() {
                let Some(&viewing_pubkey) = held.iter().find(|key| key.u() == slot.view_tag) else {
                    continue;
                };
                opened.extend(self.open(DepositSlot {
                    deposit,
                    position,
                    viewing_pubkey,
                })?);
            }
        }
        Ok(opened)
    }

    /// A deposit's published hash, not its decryption, proves it the owner's.
    pub(crate) fn open(
        &self,
        slot: DepositSlot<'_>,
    ) -> Result<Option<OpenedDeposit>, AnonymousError> {
        let DepositSlot {
            deposit,
            position,
            viewing_pubkey,
        } = slot;
        let slot = &deposit.output_slots[position];
        let context = &slot.output_context;
        let Ok(output) = decode_encrypted_ring_deposit_output_data(&slot.payload) else {
            return Ok(None);
        };
        let Ok(tx_viewing_pubkey) = X25519Pubkey::from_bytes(output.encrypted.tx_viewing_pk) else {
            return Ok(None);
        };
        if !is_contributory(&tx_viewing_pubkey) {
            return Ok(None);
        }
        let ciphertext = match (self.deposit_payload)(&output.encrypted.ciphertext) {
            Ok(wrapped) => wrapped.unwrap_or(&output.encrypted.ciphertext),
            Err(_) => return Ok(None),
        };
        let request = DecryptRequest {
            ciphertext,
            viewing_pubkey,
            tx_viewing_pubkey,
            salt: output.encrypted.salt,
            slot_index: 0,
            label: DecryptLabel::RingDeposit,
        };
        let plaintext = Zeroizing::new(exactly_one(self.keys.decrypt(&[request])?)?);
        let Ok(plaintext) = RingDepositPlaintext::deserialize(&plaintext) else {
            return Ok(None);
        };
        let asset = match self.assets.mint(&Address::new_from_array(output.asset)) {
            Ok(asset) => asset,
            Err(TransactionError::UnknownMint(mint)) => {
                return Ok(Some(OpenedDeposit::UnknownMint(mint)))
            }
            Err(_) => return Ok(None),
        };
        let utxo = plaintext.into_utxo(
            self.address.signing_pubkey,
            asset,
            output.amount,
            Address::new_from_array(output.ring_program_id),
        );
        let data_hash = output.data_hash.unwrap_or_default();
        // Utxo data under a zero data hash is unbound.
        if utxo.data.utxo_data().is_some() && data_hash == [0; 32] {
            return Ok(None);
        }
        let rebuilt = utxo.hash(
            &self.address.nullifier_pubkey,
            &data_hash,
            &output.ring_data_hash,
            context.tree_id,
        );
        if !rebuilt.is_ok_and(|hash| hash == context.hash) {
            return Ok(None);
        }
        Ok(Some(OpenedDeposit::Note(Box::new(WalletUtxo {
            utxo,
            nullifier_pubkey: self.address.nullifier_pubkey,
            utxo_hash: context.hash,
            nullifier: [0; 32],
            tx_viewing_key: None,
            data_hash: output.data_hash,
            ring_data_hash: Some(output.ring_data_hash),
            tree_id: context.tree_id,
            leaf_index: context.leaf_index,
            latest_tree_id: None,
            slot: deposit.slot,
            tx_signature: deposit.tx_signature,
            slot_index: u32::try_from(position).map_err(|_| TransactionError::TooManyOutputs)?,
        }))))
    }
}

#[cfg(test)]
mod tests {
    use custom_ring_interface::RingDepositAuditCapsule;
    use spr_keypair::ViewingKey;

    use crate::deposit_payload;
    use zolana_ring_transaction::RingDepositPlaintext;

    #[test]
    fn recipient_opens_plain_and_auditor_wrapped_ciphertexts() {
        let recipient = ViewingKey::new();
        let plaintext = RingDepositPlaintext {
            blinding: [7; 32],
            utxo_data: Some(vec![1, 2]),
            memo: Some(vec![3]),
            ring_data: vec![4],
        };
        let mut encrypted = plaintext.encrypt(&recipient.pubkey()).unwrap();
        assert_eq!(
            RingDepositPlaintext::decrypt(&encrypted, &recipient).unwrap(),
            plaintext
        );
        assert_eq!(deposit_payload(&encrypted.ciphertext).unwrap(), None);
        encrypted.ciphertext = RingDepositAuditCapsule {
            slot_index: 7,
            eph_pk: &[2; 33],
            ciphertext: &[3; custom_ring_interface::RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN],
            recipient_ciphertext: &encrypted.ciphertext,
        }
        .encode();
        let wrapped = encrypted.ciphertext.clone();
        encrypted.ciphertext = deposit_payload(&wrapped).unwrap().unwrap().to_vec();
        assert_eq!(
            RingDepositPlaintext::decrypt(&encrypted, &recipient).unwrap(),
            plaintext
        );
        assert!(deposit_payload(
            &wrapped[..custom_ring_interface::RING_DEPOSIT_AUDIT_PREFIX_LEN - 1]
        )
        .is_err());
    }
}
