//! Deposits whose proof binds the SPP deposit bytes and, under key escrow, the recipient's record.

use custom_ring_interface::{
    domain::deposit_blinding, key_catalog::RingCircuit, tag, AuditedDepositPrefix, CoSignScope,
    CustomRingError, CustomRingProof, DepositContext, DepositPublicInput, RingDepositAuditCapsule,
    RingMode,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_signature::Signature;
use solana_signer::Signer;
use spr_client::{AsyncRpc, ClientError};
use spr_interface::{pda, state::SplAssetRegistry, PROGRAM_ID_PUBKEY};
use spr_keypair::{random_blinding, Curve, ShieldedAddress, X25519Pubkey};
use spr_program::instruction::{DepositAsset, RingAssetDeposit};
use spr_transaction::{owner_utxo_hash, Data, Mint, Utxo, SOL_ASSET_ID, SOL_MINT};
use zeroize::Zeroizing;
use zolana_ring_client::{
    seal_deposits, AdvancedTag, AsyncRingIndexer, DepositEncryption, DepositOpening, FirstContact,
    PaymentRecipient, ViewingHistory,
};
use zolana_ring_keys::RingAddress;
use zolana_ring_transaction::RingDepositPlaintext;

use crate::client::{RingClient, RingIndexerBackend};
use crate::{
    co_signer::CoSignerChoice,
    pipeline::{HiddenOwner, RingSender},
    projection::retry_projection_lag,
    prover::{to_instruction_proof, RingRequest},
    records::{EscrowOpening, EscrowRead},
    request::{DepositRequest, RecordOpeningRequest},
    submission::BoundRoot,
    CustomRing, RingError, RingSubmission, SettledSubmission,
};

#[cfg(test)]
#[path = "../tests/operations/deposit.rs"]
mod tests;

#[derive(Clone, Copy)]
pub enum DepositRecipient<'a> {
    /// The member finds the note under its viewing key's tag.
    Confidential(ShieldedAddress),
    /// The depositor's own hidden identity on an anonymous ring, under its next sender tag.
    Anonymous {
        keys: &'a dyn RingSender,
        history: &'a ViewingHistory,
    },
    /// Another member of an anonymous ring, its tag by the selection over the depositor's history.
    AnonymousPayment {
        keys: &'a dyn RingSender,
        history: &'a ViewingHistory,
        to: &'a RingAddress,
        first_contact: FirstContact,
    },
}

struct TaggedRecipient {
    address: ShieldedAddress,
    view_tag: [u8; 32],
    history: Option<ViewingHistory>,
}

impl DepositRecipient<'_> {
    fn tagged(&self, ring: CustomRing) -> Result<TaggedRecipient, RingError> {
        Ok(match *self {
            Self::Confidential(address) => TaggedRecipient {
                address,
                view_tag: address.viewing_pubkey.u(),
                history: None,
            },
            Self::Anonymous { keys, history } => {
                let AdvancedTag { tag, history } = history.sender_tag(keys)?;
                TaggedRecipient {
                    address: keys.address()?,
                    view_tag: tag,
                    history: Some(history),
                }
            }
            Self::AnonymousPayment {
                keys,
                history,
                to,
                first_contact,
            } => {
                if to.ring_program_id != ring.program_id() {
                    return Err(RingError::ForeignRingAddress {
                        address: to.ring_program_id,
                        ring: ring.program_id(),
                    });
                }
                let AdvancedTag { tag, history } = history.deposit_tag(
                    keys,
                    &PaymentRecipient {
                        viewing_pubkey: to.recipient.viewing_pubkey,
                        first_contact,
                    },
                )?;
                TaggedRecipient {
                    address: to.recipient,
                    view_tag: tag.payment.tag,
                    history: Some(history),
                }
            }
        })
    }
}

#[must_use]
pub struct RingDeposit<'a> {
    pub ring: CustomRing,
    /// Lamport source for Sol, the user token's authority for Spl.
    pub payer: &'a (dyn Signer + Sync),
    pub recipient: DepositRecipient<'a>,
    pub tree: Address,
    pub asset: DepositAsset,
    pub amount: u64,
    /// Signs when a record covers deposits, the record must be its own.
    pub cosigner: Option<&'a (dyn Signer + Sync)>,
}

pub struct RingDepositReceipt {
    pub signature: Signature,
    pub utxo: Utxo,
}

/// A deposit whose note and auditor ciphertext are fixed, the proof is not.
#[must_use]
pub struct PreparedRingDeposit {
    ring: CustomRing,
    spp: Instruction,
    cosigner: Option<Address>,
    utxo: Utxo,
    disclosure: DepositDisclosure,
    viewing_history: Option<ViewingHistory>,
}

pub(crate) struct BoundDeposit {
    pub instruction: Instruction,
    /// `None` without key escrow.
    pub root: Option<BoundRoot>,
}

struct DepositDisclosure {
    /// The Ed25519 owner key an anonymous ring discloses, the proof binds it to the owner hash.
    owner_key: Option<[u8; 32]>,
    context_hash: [u8; 32],
    owner_utxo_hash: [u8; 32],
    owner_pk_hash: [u8; 32],
    nullifier_pk: [u8; 32],
    blinding_secret: Zeroizing<[u8; 32]>,
    encryption: DepositEncryption,
    auditor: X25519Pubkey,
    /// The recipient's record must escrow the key the note uses.
    escrow: bool,
}

impl RingDeposit<'_> {
    /// The depositor's viewing history past the deposit's tag, stored before it is sent.
    pub fn viewing_history(&self) -> Result<Option<ViewingHistory>, RingError> {
        Ok(self.recipient.tagged(self.ring)?.history)
    }

    /// Fixes the note, every proving attempt deposits the same one.
    pub async fn prepare(
        &self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<PreparedRingDeposit, RingError> {
        let mint = self.asset.mint();
        let mint = Mint::new(mint, fetch_asset_id_async(rpc, mint).await?);
        let config = self.ring.require_config(rpc).await?;
        self.ring.require_active(rpc).await?;
        let anonymous = config.mode == RingMode::Anonymous;
        if anonymous == matches!(self.recipient, DepositRecipient::Confidential(_)) {
            return Err(match anonymous {
                true => CustomRingError::AnonymousRingRefused.into(),
                false => RingError::NotAnonymousRing,
            });
        }
        let TaggedRecipient {
            address,
            view_tag,
            history: viewing_history,
        } = self.recipient.tagged(self.ring)?;
        let owner_key = match anonymous {
            // An anonymous ring spends only through the hidden Ed25519 proof.
            true if address.signing_pubkey.curve()? != Curve::Ed25519 => {
                return Err(RingError::AnonymousRecipient)
            }
            true => Some(address.signing_pubkey.as_ed25519()?),
            false => None,
        };
        if let Some(owner) = owner_key {
            HiddenOwner(Address::new_from_array(owner)).check_signers(
                core::iter::once(self.payer.pubkey())
                    .chain(self.cosigner.map(|signer| signer.pubkey())),
            )?;
        }
        let blinding_secret = Zeroizing::new(random_blinding());
        let blinding = deposit_blinding(&blinding_secret)?;
        let owner_hash = address.owner_hash()?;
        let mut deposit = RingAssetDeposit {
            asset: self.asset,
            view_tag,
            owner_utxo_hash: owner_utxo_hash(&owner_hash, &blinding)?,
            amount: self.amount,
            ring_data_hash: [0; 32],
            encrypted: RingDepositPlaintext {
                blinding,
                utxo_data: None,
                memo: None,
                ring_data: Vec::new(),
            }
            .encrypt(&address.viewing_pubkey)?,
        };
        let encryption = seal_deposits(
            &[DepositOpening {
                owner_hash,
                blinding: Zeroizing::new(blinding),
                owner_key,
            }],
            &config.auditor_pubkey,
        )?;
        deposit.encrypted.ciphertext = RingDepositAuditCapsule {
            slot_index: 0,
            eph_pk: encryption.ephemeral_pk.as_bytes(),
            ciphertext: &encryption.ciphertexts[0],
            recipient_ciphertext: &deposit.encrypted.ciphertext,
        }
        .encode();
        // The proof binds the ring, the tree and the exact forwarded SPP bytes.
        let spp = spr_program::instruction::RingDeposit {
            tree: self.tree,
            depositor: self.payer.pubkey(),
            ring_program_id: self.ring.program_id(),
            deposits: vec![deposit.clone()],
        }
        .instruction()?;
        let cosigner = CoSignerChoice {
            ring: self.ring,
            config: &config,
            demand: &custom_ring_interface::cosign::CoSignDemand {
                approval_required: false,
                classes: CoSignScope::DEPOSITS,
                withdrawals: Vec::new(),
            },
            supplied: self.cosigner.map(|signer| signer.pubkey()),
        }
        .resolve(rpc)
        .await?;
        Ok(PreparedRingDeposit {
            ring: self.ring,
            cosigner,
            utxo: Utxo {
                owner: address.signing_pubkey,
                asset: mint,
                amount: self.amount,
                blinding,
                ring_program_id: Some(self.ring.program_id()),
                data: Data::default(),
            },
            disclosure: DepositDisclosure {
                owner_key,
                context_hash: DepositContext {
                    program_id: self.ring.program_id().as_array(),
                    tree: self.tree.as_array(),
                    spp_data: &spp.data,
                }
                .hash()?,
                owner_utxo_hash: deposit.owner_utxo_hash,
                owner_pk_hash: address.signing_pubkey.owner_proof_input_hash()?,
                nullifier_pk: address.nullifier_pubkey,
                blinding_secret,
                encryption,
                auditor: config.auditor_pubkey,
                escrow: config.mode == RingMode::ConfidentialEscrow,
            },
            spp,
            viewing_history,
        })
    }

    pub async fn send<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
    ) -> Result<RingDepositReceipt, RingError> {
        self.send_with_fee_payer(client, self.payer).await
    }

    /// Sponsors transaction fees while the deposit source still authorizes its funds.
    pub async fn send_with_fee_payer<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
        fee_payer: &(dyn Signer + Sync),
    ) -> Result<RingDepositReceipt, RingError> {
        let prepared = self.prepare(client.zolana()).await?;
        let utxo = prepared.utxo.clone();
        let signers = self.signers(&prepared);
        match RingSubmission::new(prepared)
            .send_until_settled(client, fee_payer, &signers)
            .await?
        {
            SettledSubmission::Confirmed { signature, .. } => {
                Ok(RingDepositReceipt { signature, utxo })
            }
            SettledSubmission::Failed { signature, error } => {
                Err(RingError::Rejected { signature, error })
            }
        }
    }

    /// A co-signer the ring does not demand is no account of the deposit and cannot sign it.
    pub(crate) fn signers(&self, prepared: &PreparedRingDeposit) -> Vec<&(dyn Signer + Sync)> {
        core::iter::once(self.payer)
            .chain(self.cosigner.filter(|_| prepared.cosigner.is_some()))
            .collect()
    }
}

impl PreparedRingDeposit {
    pub(crate) fn check_public_signers(
        &self,
        signers: impl IntoIterator<Item = Address>,
    ) -> Result<(), RingError> {
        match self.disclosure.owner_key {
            Some(owner) => HiddenOwner(Address::new_from_array(owner)).check_signers(signers),
            None => Ok(()),
        }
    }

    pub fn utxo(&self) -> &Utxo {
        &self.utxo
    }

    pub fn viewing_history(&self) -> Option<&ViewingHistory> {
        self.viewing_history.as_ref()
    }

    /// Each call binds the newest root, a raised floor needs only a new proof.
    pub async fn prove<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
    ) -> Result<Instruction, RingError> {
        Ok(self.prove_bound(client).await?.instruction)
    }

    pub(crate) async fn prove_bound<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
    ) -> Result<BoundDeposit, RingError> {
        let disclosure = &self.disclosure;
        retry_projection_lag(|| async {
            let root = match disclosure.escrow {
                true => Some(BoundRoot::newest(self.ring, client.zolana()).await?),
                false => None,
            };
            let record = match root {
                Some(root) => Some(disclosure.record(client.zolana(), root).await?),
                None => None,
            };
            let body = disclosure.body(root.map(|root| root.root), record.as_ref())?;
            let proof = RingRequest::new(RingCircuit::deposit(body.count as u8), &*body)?
                .prove(client, body.public_input_hash)
                .await?;
            Ok(BoundDeposit {
                instruction: self.instruction(to_instruction_proof(proof)?, root)?,
                root,
            })
        })
        .await
    }

    /// `[config, policy?, co-signer?]`, then SPP's deposit list.
    fn instruction(
        &self,
        proof: CustomRingProof,
        root: Option<BoundRoot>,
    ) -> Result<Instruction, RingError> {
        let mut instruction = self.spp.clone();
        let prefix = AuditedDepositPrefix {
            tag: tag::AUDITED_DEPOSIT,
            proof,
            own_revision: root.map_or_else(Default::default, |root| root.revision),
        };
        instruction.data = [bytemuck::bytes_of(&prefix), &instruction.data].concat();
        let mut accounts = vec![AccountMeta::new_readonly(self.ring.config_pda(), false)];
        if root.is_some() {
            accounts.push(AccountMeta::new_readonly(self.ring.policy_pda(), false));
        }
        accounts.extend(
            self.cosigner
                .into_iter()
                .flat_map(|cosigner| self.ring.co_signer_metas(cosigner)),
        );
        instruction.accounts.splice(0..0, accounts);
        Ok(instruction)
    }
}

impl DepositDisclosure {
    /// The recipient's record under `root`, it must escrow the deposited key.
    async fn record(
        &self,
        rpc: &(impl AsyncRpc + AsyncRingIndexer + ?Sized),
        root: BoundRoot,
    ) -> Result<EscrowOpening, RingError> {
        EscrowRead {
            root,
            owner: self.owner_pk_hash,
            nullifier_pk: self.nullifier_pk,
        }
        .read(rpc)
        .await
    }

    fn body(
        &self,
        root: Option<[u8; 32]>,
        record: Option<&EscrowOpening>,
    ) -> Result<Box<DepositRequest>, RingError> {
        let public_input_hash = DepositPublicInput {
            context_hash: &self.context_hash,
            anonymous: self.owner_key.is_some(),
            owner_utxo_hashes: &[self.owner_utxo_hash],
            ciphertexts: &self.encryption.ciphertexts,
            auditor_pk: self.auditor.as_bytes(),
            eph_pk: self.encryption.ephemeral_pk.as_bytes(),
            member_registry_root: root.as_ref(),
        }
        .hash()?;
        let first = |value: [u8; 32]| [value];
        let mut members: [Option<RecordOpeningRequest>; 1] = Default::default();
        members[0] = record.map(|record| record.opening.clone());
        Ok(Box::new(DepositRequest {
            public_input_hash,
            context_hash: self.context_hash,
            count: 1,
            anonymous: self.owner_key.is_some(),
            owner_pk_hashes: first(self.owner_pk_hash),
            owner_keys: self.owner_key.map(first),
            nullifier_pks: first(self.nullifier_pk),
            blinding_secrets: Zeroizing::new(first(*self.blinding_secret)),
            ct_hashes: first(record.map_or([0; 32], |record| record.ct_hash)),
            members,
            eph_sk: self.encryption.ephemeral_sk.clone(),
            auditor_pk: self.auditor,
            key_escrow: root.is_some(),
            member_registry_root: root.unwrap_or_default(),
        }))
    }
}

/// The asset id SPP keys `asset` by, SOL without a read, an SPL mint from its registry account.
pub async fn fetch_asset_id_async<R: AsyncRpc + ?Sized>(
    rpc: &R,
    asset: Address,
) -> Result<u64, ClientError> {
    if asset == SOL_MINT {
        return Ok(SOL_ASSET_ID);
    }
    let not_registered = || ClientError::SplAssetNotRegistered { mint: asset };
    let account = rpc
        .get_account(pda::spl_asset_registry(&asset))
        .await?
        .ok_or_else(not_registered)?;
    // Any other owner means lamports were sent there, not that the mint was registered.
    if account.owner != PROGRAM_ID_PUBKEY {
        return Err(not_registered());
    }
    let invalid = || ClientError::InvalidSplAssetRegistry { mint: asset };
    let registry = SplAssetRegistry::from_account_bytes(&account.data).map_err(|_| invalid())?;
    if registry.mint != asset {
        return Err(invalid());
    }
    Ok(registry.asset_id)
}
