//! The wallet half of a relayed transfer, Ring RPC reads the Merkle paths and records and proves.

use solana_address::Address;
use solana_signature::Signature;
use spr_client::AsyncRpc;
use spr_indexer_api::{Hash, SerializablePubkey, SerializableSignature};
use spr_keypair::{NullifierKey, PublicKey, SigningKey};
use spr_program::instruction::CreateAssociatedTokenAccount;
use spr_transaction::instructions::transact::{SettlementTransfer, SppProofOutputUtxo};
use zolana_ring_client::rpc::{
    PrepareRelayRequest, ProofInputBytes, RelayCoOwner, RelayIntent, RelayProofInputs, RelayQuote,
    RelayRail, TokenAccountSetup,
};
use zolana_ring_transaction::{published_outputs, ClassifiedInput, RingDelivery};

use zolana_ring_policy::OwnerDebit;

use super::{
    approval_totals_of, charged_outflows_of, owner::deposit_funder, Anonymous, Delegated, Owner,
    Planned, Rail, RingTransfer, Sealed,
};
use crate::{
    relay_message::{
        ApprovalOpening, ExpectedMessage, FundedLeg, RelayFunderTerms, RelayTransferTerms,
        SealedTerms, SlotOpening, TokenAccountCreate,
    },
    PreparedRelay, RingError,
};

/// The hidden or in-proof owner's signature waits on [`Self::sign`], the charges read first.
#[must_use = "sign the relay"]
pub struct UnsignedRelay<'t> {
    signer: &'t SigningKey,
    message_hash: [u8; 32],
    intent: UnsignedIntent,
    ring: SerializablePubkey,
    quote: RelayQuote,
    co_signers: Vec<SerializablePubkey>,
    expected: SealedTerms,
}

enum UnsignedIntent {
    Anonymous(ProofInputBytes, Vec<TokenAccountSetup>),
    Confidential(ProofInputBytes, Vec<TokenAccountSetup>),
}

impl UnsignedRelay<'_> {
    pub fn charged_outflows(&self) -> &[OwnerDebit] {
        &self.expected.charged_outflows
    }

    pub fn sign(self) -> Result<PreparedRelay, RingError> {
        let owner_signature = SerializableSignature(Signature::from(
            self.signer.sign_message(&self.message_hash)?,
        ));
        let intent = match self.intent {
            UnsignedIntent::Anonymous(proof_inputs, token_account_setup) => {
                RelayIntent::Anonymous {
                    proof_inputs,
                    owner_signature,
                    token_account_setup,
                }
            }
            UnsignedIntent::Confidential(proof_inputs, token_account_setup) => {
                RelayIntent::Confidential {
                    proof_inputs,
                    owner_signature,
                    token_account_setup,
                }
            }
        };
        Ok(PreparedRelay::new(PrepareRelayRequest {
            ring: self.ring,
            quote: self.quote,
            intent,
            co_signers: self.co_signers,
        })
        .expecting(ExpectedMessage::Sealed(self.expected)))
    }
}

impl RingTransfer<Anonymous<'_>> {
    /// The wallet reads no Merkle path and no record.
    pub async fn prepare_relay<C: AsyncRpc + ?Sized>(
        &self,
        client: &C,
        quote: RelayQuote,
    ) -> Result<UnsignedRelay<'_>, RingError> {
        WalletRelay {
            transfer: self,
            owner: &self.rail.owner,
            signer: self.rail.signer,
            exit_token_owner: self.rail.exit_token_owner,
        }
        .prepare(client, quote)
        .await
    }
}

impl RingTransfer<Owner<'_>> {
    /// The wallet reads no Merkle path and no record.
    pub async fn prepare_relay<C: AsyncRpc + ?Sized>(
        &self,
        client: &C,
        quote: RelayQuote,
    ) -> Result<UnsignedRelay<'_>, RingError> {
        WalletRelay {
            transfer: self,
            owner: &self.rail,
            signer: self
                .rail
                .in_proof_owner
                .ok_or(RingError::MissingInProofOwnerSignature)?,
            exit_token_owner: None,
        }
        .prepare(client, quote)
        .await
    }
}

struct WalletRelay<'t, R: Rail> {
    transfer: &'t RingTransfer<R>,
    owner: &'t Owner<'t>,
    signer: &'t SigningKey,
    exit_token_owner: Option<Address>,
}

impl<'t, R: Rail> WalletRelay<'t, R> {
    async fn prepare<C: AsyncRpc + ?Sized>(
        self,
        client: &C,
        quote: RelayQuote,
    ) -> Result<UnsignedRelay<'t>, RingError> {
        let payer = self.owner.transaction.payer();
        if payer != quote.fee_payer.0 {
            return Err(RingError::RelayPayerMismatch {
                payer,
                fee_payer: quote.fee_payer.0,
            });
        }
        let sealed = self.transfer.seal_unread(client).await?;
        let staged = &sealed.pipeline.staged;
        let inputs = &staged.proof_inputs;
        let nullifier_key = staged
            .authority
            .owner
            .clone()
            .ok_or(RingError::MissingAnonymousSigner)?;
        let token_account_setup = self.owner.token_account_setup.clone();
        // The relay refuses a setup naming no withdrawal, only an owner's terms read it here.
        let setup = match staged.owner_signers.is_empty() {
            true => Vec::new(),
            false => sealed
                .relay_proof_inputs(RelayRail::Confidential, nullifier_key.clone())
                .token_account_setup(payer, &token_account_setup)?,
        };
        let terms = sealed.transfer_terms(payer, &setup)?;
        let funders = sealed.funder_terms(payer, &setup)?;
        let approval = sealed
            .pipeline
            .approval_blinder
            .map(|blinder| {
                let totals = approval_totals_of(inputs, sealed.policy.plan().stream.capacity)?;
                Ok::<_, RingError>(ApprovalOpening::of(&totals, &blinder))
            })
            .transpose()?;
        let encode = |rail| {
            sealed
                .relay_proof_inputs(rail, nullifier_key)
                .encode()
                .map(ProofInputBytes::new)
                .map_err(RingError::from)
        };
        let intent = match staged.rail.delivery() {
            RingDelivery::Anonymous(plan) => UnsignedIntent::Anonymous(
                encode(RelayRail::Anonymous {
                    plan: plan.clone(),
                    exit_token_owner: self.exit_token_owner,
                })?,
                token_account_setup,
            ),
            RingDelivery::Delivered => {
                UnsignedIntent::Confidential(encode(RelayRail::Confidential)?, token_account_setup)
            }
        };
        Ok(UnsignedRelay {
            signer: self.signer,
            message_hash: inputs.message_hash()?,
            intent,
            ring: SerializablePubkey(self.transfer.ring.program_id()),
            quote,
            co_signers: self
                .transfer
                .co_signers
                .iter()
                .copied()
                .map(SerializablePubkey)
                .collect(),
            expected: SealedTerms {
                owners: terms,
                funders,
                approval,
                charged_outflows: charged_outflows_of(inputs)?,
            },
        })
    }
}

impl<R: Rail> RingTransfer<R> {
    /// A frame of only dummies, each funder reads its legs and signs the message Ring RPC returns.
    pub(crate) async fn deposit_relay<C: AsyncRpc + ?Sized>(
        &self,
        client: &C,
    ) -> Result<(RelayProofInputs, SealedTerms), RingError> {
        let sealed = self.seal_unread(client).await?;
        let staged = &sealed.pipeline.staged;
        let inputs = &staged.proof_inputs;
        let plan = match staged.rail.delivery() {
            RingDelivery::Anonymous(plan) => Some(plan.clone()),
            RingDelivery::Delivered => None,
        };
        let nullifier_key = staged
            .authority
            .owner
            .clone()
            .ok_or(RingError::NullifierKeyMismatch)?;
        let terms = SealedTerms {
            owners: Vec::new(),
            funders: sealed.funder_terms(inputs.payer, &[])?,
            approval: None,
            charged_outflows: charged_outflows_of(inputs)?,
        };
        Ok((
            sealed.relay_proof_inputs(RelayRail::Deposit { plan }, nullifier_key),
            terms,
        ))
    }
}

impl RingTransfer<Delegated<'_>> {
    /// Reads accounts only, the relayed delegate rail proves the result.
    pub async fn relay_proof_inputs<C: AsyncRpc + ?Sized>(
        &self,
        client: &C,
    ) -> Result<RelayProofInputs, RingError> {
        let sealed = self.seal_unread(client).await?;
        let plan = match sealed.pipeline.staged.rail.delivery() {
            RingDelivery::Anonymous(plan) => Some(plan.clone()),
            RingDelivery::Delivered => None,
        };
        Ok(sealed.relay_proof_inputs(
            RelayRail::Delegate {
                delegate: self.rail.delegate,
                plan,
            },
            self.rail.source_key.clone(),
        ))
    }
}

impl<P: Planned> Sealed<'_, P> {
    /// One per key funding a deposit leg, the payer and an owner of the run left out. The payer pays
    /// the message it builds, and an owner's check refuses a key named beside its run entry.
    fn funder_terms(
        &self,
        fee_payer: Address,
        setup: &[CreateAssociatedTokenAccount],
    ) -> Result<Vec<RelayFunderTerms>, RingError> {
        let staged = &self.pipeline.staged;
        let transfers = &staged.proof_inputs.external_data.interface_transfers;
        let ring = self.pipeline.ring.program_id();
        let setup = token_account_creates(setup);
        let mut terms: Vec<RelayFunderTerms> = Vec::new();
        for (transfer, accounts) in transfers.iter().zip(&staged.interface_transfer_accounts) {
            let Some(funder) = deposit_funder(&transfer.interface_transfer(), accounts) else {
                continue;
            };
            if funder == fee_payer || staged.owner_signers.contains(&funder) {
                continue;
            }
            let leg = FundedLeg {
                mint: match transfer {
                    SettlementTransfer::Spl { mint, .. } => Some(SerializablePubkey(*mint)),
                    SettlementTransfer::Sol { .. } => None,
                },
                amount: transfer.interface_transfer().amount(),
            };
            match terms.iter_mut().find(|held| held.signer.0 == funder) {
                Some(held) => held.legs.push(leg),
                None => terms.push(RelayFunderTerms {
                    ring: SerializablePubkey(ring),
                    fee_payer: SerializablePubkey(fee_payer),
                    signer: SerializablePubkey(funder),
                    legs: vec![leg],
                    setup: setup.clone(),
                }),
            }
        }
        Ok(terms)
    }

    /// One per public owner, every published slot and its own notes.
    fn transfer_terms(
        &self,
        fee_payer: Address,
        setup: &[CreateAssociatedTokenAccount],
    ) -> Result<Vec<RelayTransferTerms>, RingError> {
        let staged = &self.pipeline.staged;
        let inputs = &staged.proof_inputs;
        let ring = self.pipeline.ring.program_id();
        let setup = token_account_creates(setup);
        let slots = published_outputs(&inputs.output_utxos)
            .iter()
            .zip(0u32..)
            .map(|(output, slot)| slot_opening(output, slot, inputs.output_tree_id))
            .collect::<Result<Vec<_>, RingError>>()?;
        Ok(staged
            .owner_signers
            .iter()
            .map(|signer| {
                let key = PublicKey::from_ed25519(signer.as_array());
                RelayTransferTerms {
                    ring: SerializablePubkey(ring),
                    fee_payer: SerializablePubkey(fee_payer),
                    signer: SerializablePubkey(*signer),
                    slots: slots.clone(),
                    nullifiers: inputs
                        .input_utxos
                        .iter()
                        .filter(|input| input.is_note() && input.utxo.owner == key)
                        .map(|input| Hash(input.nullifier()))
                        .collect(),
                    setup: setup.clone(),
                }
            })
            .collect())
    }

    fn relay_proof_inputs(&self, rail: RelayRail, nullifier_key: NullifierKey) -> RelayProofInputs {
        let staged = &self.pipeline.staged;
        let inputs = &staged.proof_inputs;
        RelayProofInputs {
            rail,
            ring_program_id: self.pipeline.ring.program_id(),
            sender: staged.sender,
            nullifier_key,
            co_owners: staged
                .authority
                .co_owners
                .iter()
                .map(|held| RelayCoOwner {
                    owner: held.owner,
                    nullifier_key: held.key.clone(),
                })
                .collect(),
            tx_viewing_key: staged.rail.tx_viewing_key().clone(),
            inputs: inputs.input_utxos.clone(),
            outputs: inputs.output_utxos.clone(),
            external_data: inputs.external_data.clone(),
            interface_transfer_accounts: staged.interface_transfer_accounts.clone(),
            blinding_seed: inputs.blinding_seed,
            output_tree_id: inputs.output_tree_id,
            list_salts: staged.list_salts.clone(),
            wide_owners: self.policy.plan().key.wide,
            approval_blinder: self.pipeline.approval_blinder,
        }
    }
}

/// A dummy opens under the zero owner with its blinding alone.
fn slot_opening(
    output: &SppProofOutputUtxo,
    slot: u32,
    tree_id: u16,
) -> Result<SlotOpening, RingError> {
    let blinding = Hash(output.blinding);
    let Some(owner) = output.owner_address else {
        return Ok(SlotOpening {
            slot,
            owner: SerializablePubkey(Address::default()),
            nullifier_pk: Hash([0; 32]),
            mint: SerializablePubkey(Address::default()),
            amount: 0,
            blinding,
            tree_id,
            data_hash: Hash([0; 32]),
            ring_data_hash: Hash([0; 32]),
        });
    };
    Ok(SlotOpening {
        slot,
        owner: SerializablePubkey(Address::new_from_array(
            owner.signing_pubkey.confidential_view_tag()?,
        )),
        nullifier_pk: Hash(owner.nullifier_pubkey),
        mint: SerializablePubkey(output.asset.asset),
        amount: output.amount,
        blinding,
        tree_id,
        data_hash: Hash(output.data_hash.unwrap_or_default()),
        ring_data_hash: Hash(output.ring_data_hash.unwrap_or_default()),
    })
}

fn token_account_creates(setup: &[CreateAssociatedTokenAccount]) -> Vec<TokenAccountCreate> {
    setup
        .iter()
        .map(|create| TokenAccountCreate {
            owner: SerializablePubkey(create.owner),
            mint: SerializablePubkey(create.mint),
            token_program: SerializablePubkey(create.token_program),
        })
        .collect()
}

#[cfg(test)]
#[path = "../../tests/operations/relay.rs"]
mod tests;
