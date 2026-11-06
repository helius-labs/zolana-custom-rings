use serde::{Deserialize, Serialize};
use solana_address::Address;
use spr_indexer_api::{Base64String, Context, Hash, SerializablePubkey, SerializableSignature};

use super::{
    DecryptedDefaultInput, DecryptedOutput, DecryptedTransaction, DecryptedWithdrawal, PagedRead,
    ReadRequest, ReadTarget,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetWalletActivityResponse {
    pub context: Context,
    pub value: WalletActivityPage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WalletActivityPage {
    pub items: Vec<WalletActivity>,
    pub cursor: Option<Base64String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WalletActivity {
    pub slot: u64,
    pub tx_signature: SerializableSignature,
    pub event_index: u16,
    pub view: WalletView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "role",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum WalletView {
    /// The anonymous sender or a named spender, a co-owner reads its own notes alone.
    Sender {
        /// Nullifiers of the wallet's own spent notes the service resolved.
        spent: Vec<Hash>,
        /// The wallet's own default-ring notes.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        default_inputs: Vec<DecryptedDefaultInput>,
        outputs: Vec<DecryptedOutput>,
        withdrawals: Vec<DecryptedWithdrawal>,
    },
    Recipient {
        outputs: Vec<DecryptedOutput>,
        withdrawals: Vec<DecryptedWithdrawal>,
    },
}

impl WalletActivity {
    pub fn read(target: ReadTarget, wallet: Address) -> ReadRequest {
        PagedRead::WalletActivity
            .request(target)
            .with_wallet(wallet)
    }

    /// A wallet owning all `R` spent notes keeps every output as its own payment, else only its own
    /// outputs.
    pub fn of(
        wallet: Address,
        transaction: DecryptedTransaction,
        owns: impl Fn(&Hash) -> bool,
    ) -> Option<Self> {
        let DecryptedTransaction {
            slot,
            tx_signature,
            event_index,
            outputs,
            real_inputs,
            default_inputs,
            nullifiers,
            spenders,
            withdrawals,
            ..
        } = transaction;
        let names = |key: SerializablePubkey| key.0 == wallet;
        let spent: Vec<Hash> = nullifiers
            .into_iter()
            .filter(|nullifier| owns(nullifier))
            .collect();
        let default_inputs: Vec<DecryptedDefaultInput> = default_inputs
            .into_iter()
            .filter(|input| names(input.owner_key))
            .collect();
        let own_notes = spent.len() + default_inputs.len();
        let spent_own = own_notes > 0;
        let view = match spent_own || spenders.into_iter().any(names) {
            true => {
                // A named spender of no input signed only its own outputs.
                let sole_owner = spent_own && own_notes == usize::from(real_inputs);
                WalletView::Sender {
                    spent,
                    default_inputs,
                    outputs: outputs
                        .into_iter()
                        .filter(|output| sole_owner || output.owner_key().is_some_and(names))
                        .collect(),
                    withdrawals,
                }
            }
            false => {
                let outputs: Vec<_> = outputs
                    .into_iter()
                    .filter(|output| output.owner_key().is_some_and(names))
                    .collect();
                if outputs.is_empty() {
                    return None;
                }
                WalletView::Recipient {
                    outputs,
                    withdrawals: withdrawals
                        .into_iter()
                        .filter(|leg| names(leg.recipient) || leg.screened_owner.is_some_and(names))
                        .collect(),
                }
            }
        };
        Some(Self {
            slot,
            tx_signature,
            event_index,
            view,
        })
    }
}
