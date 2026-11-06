use serde::{Deserialize, Serialize};
use solana_address::Address;
use spr_indexer_api::{Base64String, Context, SerializablePubkey, SerializableSignature};

use super::{
    DecryptedInput, DecryptedOutput, DecryptedTransaction, DecryptedWithdrawal, PagedRead,
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
        inputs: Vec<DecryptedInput>,
        outputs: Vec<DecryptedOutput>,
        withdrawals: Vec<DecryptedWithdrawal>,
    },
    Recipient {
        outputs: Vec<DecryptedOutput>,
        withdrawals: Vec<DecryptedWithdrawal>,
    },
}

/// Who holds one published input, an input the service cannot name reads as `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputParty {
    Own,
    Other,
    Padding,
}

impl WalletActivity {
    pub fn read(target: ReadTarget, wallet: Address) -> ReadRequest {
        PagedRead::WalletActivity
            .request(target)
            .with_wallet(wallet)
    }

    /// A wallet that owns a real input and no other party's input keeps all outputs as its own payments.
    pub fn of(
        wallet: Address,
        transaction: DecryptedTransaction,
        party: impl Fn(&DecryptedInput) -> InputParty,
    ) -> Option<Self> {
        let DecryptedTransaction {
            slot,
            tx_signature,
            event_index,
            outputs,
            inputs,
            spenders,
            withdrawals,
            ..
        } = transaction;
        let names = |key: SerializablePubkey| key.0 == wallet;
        let parties: Vec<_> = inputs.iter().map(&party).collect();
        let spent_own = parties.contains(&InputParty::Own);
        let view = match spent_own || spenders.into_iter().any(names) {
            true => {
                // Dummy inputs prove no ownership, a named spender of no input signed only its own outputs.
                let sole_owner = spent_own && !parties.contains(&InputParty::Other);
                WalletView::Sender {
                    inputs: inputs
                        .into_iter()
                        .zip(parties)
                        .filter(|(_, party)| *party == InputParty::Own)
                        .map(|(input, _)| input)
                        .collect(),
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
