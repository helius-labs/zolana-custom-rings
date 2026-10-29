//! Deposits whose proof binds the SPP data and the record of any escrowed owner or screened asset.

use custom_ring_interface::{
    domain::deposit_blinding, key_catalog::RingCircuit, ring_deposit_assets, tag,
    AuditedDepositPrefix, CoSignScope, CustomRingError, CustomRingProof, DepositContext,
    DepositPublicInput, DepositRegistry, DepositedAsset, MemberRegistry, RingDepositAuditCapsule,
    RingMode,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_signature::Signature;
use solana_signer::Signer;
use spr_client::{AsyncRpc, ClientError};
use spr_hasher::primitives::right_align;
use spr_interface::{
    instruction::instruction_data::deposit::RingDepositIxDataRef, pda, state::SplAssetRegistry,
    PROGRAM_ID_PUBKEY,
};
use spr_keypair::{random_blinding, Curve, ShieldedAddress, X25519Pubkey};
use spr_program::instruction::{DepositAsset, RingAssetDeposit};
use spr_transaction::{owner_utxo_hash, Data, Mint, Utxo, SOL_ASSET_ID, SOL_MINT};
use zeroize::Zeroizing;
use zolana_ring_client::{
    seal_deposits, AdvancedTag, AsyncRingIndexer, DepositEncryption, DepositOpening, FirstContact,
    PaymentRecipient, ViewingHistory,
};
use zolana_ring_keys::RingAddress;
use zolana_ring_policy::SourceMap;
use zolana_ring_transaction::RingDepositPlaintext;

use crate::client::{RingClient, RingIndexerBackend};
use crate::{
    pipeline::{HiddenOwner, RingSender},
    projection::retry_projection_lag,
    prover::{to_instruction_proof, RingRequest},
    records::{MemberRead, OwnerRead},
    request::{DepositRequest, MemberOpening, PolicyTable, RecordOpeningRequest},
    submission::{BoundPolicy, BoundRoot},
    CustomRing, PinnedPolicy, RingError, RingSubmission, SettledSubmission,
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
    /// Signs when the config's scope covers deposits.
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
    /// `None` off an escrow or policy ring.
    pub root: Option<BoundRoot>,
    pub policy: Option<BoundPolicy>,
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
    key_escrow: bool,
    has_policy: bool,
    asset: DepositedAsset,
}

struct EscrowedRecord {
    opening: RecordOpeningRequest,
    ct_hash: [u8; 32],
}

struct DepositRecords {
    root: BoundRoot,
    escrowed: Option<EscrowedRecord>,
    policy: Option<AssetScreen>,
}

struct AssetScreen {
    registry: Box<MemberRegistry>,
    sources: SourceMap,
    policy_hash: [u8; 32],
    asset: MemberOpening,
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
        let deposit_data = RingDepositIxDataRef::from_bytes(spp.data.get(1..).unwrap_or_default())
            .map_err(|_| CustomRingError::InvalidDepositData)?;
        let [asset] = ring_deposit_assets(&deposit_data, |index| {
            spp.accounts.get(index).map(|meta| meta.pubkey.to_bytes())
        })?[..] else {
            return Err(CustomRingError::InvalidDepositData.into());
        };
        let cosigner = custom_ring_interface::cosign::CoSignDemand {
            approval_required: false,
            classes: CoSignScope::DEPOSITS,
            withdrawals: Vec::new(),
        }
        .signer(config.account())?;
        if cosigner.is_some() && cosigner != self.cosigner.map(|signer| signer.pubkey()) {
            return Err(CustomRingError::MissingCoSigner.into());
        }
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
                key_escrow: config.mode == RingMode::ConfidentialEscrow,
                has_policy: config.account().has_policy(),
                asset,
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

    /// A co-signer the config does not demand is no account of the deposit and cannot sign it.
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
            let records = match disclosure.key_escrow || disclosure.has_policy {
                true => Some(disclosure.records(self.ring, client.zolana()).await?),
                false => None,
            };
            let body = disclosure.body(records.as_ref())?;
            let proof = RingRequest::new(RingCircuit::deposit(body.count as u8), &*body)?
                .prove(client, body.public_input_hash)
                .await?;
            let root = records.as_ref().map(|records| records.root);
            Ok(BoundDeposit {
                instruction: self.instruction(to_instruction_proof(proof)?, root)?,
                root,
                policy: records
                    .as_ref()
                    .and_then(|records| records.policy.as_ref())
                    .map(|policy| BoundPolicy {
                        ring: self.ring,
                        hash: policy.policy_hash,
                    }),
            })
        })
        .await
    }

    /// `[config, registry?, co-signer?]`, then SPP's deposit list.
    fn instruction(
        &self,
        proof: CustomRingProof,
        root: Option<BoundRoot>,
    ) -> Result<Instruction, RingError> {
        let mut instruction = self.spp.clone();
        let prefix = AuditedDepositPrefix {
            tag: tag::AUDITED_DEPOSIT,
            proof,
            registry_root_index: root.map_or(0, |root| root.index),
        };
        instruction.data = [bytemuck::bytes_of(&prefix), &instruction.data].concat();
        let mut accounts = vec![AccountMeta::new_readonly(self.ring.config_pda(), false)];
        if root.is_some() {
            accounts.push(AccountMeta::new_readonly(self.ring.registry_pda(), false));
        }
        accounts.extend(
            self.cosigner
                .map(|cosigner| AccountMeta::new_readonly(cosigner, true)),
        );
        instruction.accounts.splice(0..0, accounts);
        Ok(instruction)
    }
}

impl DepositDisclosure {
    async fn records(
        &self,
        ring: CustomRing,
        rpc: &(impl AsyncRpc + AsyncRingIndexer + ?Sized),
    ) -> Result<DepositRecords, RingError> {
        let registry = ring.require_registry(rpc).await?;
        let root = BoundRoot::current(ring, &registry);
        let escrowed = match self.key_escrow {
            true => Some(self.record(rpc, root).await?),
            false => None,
        };
        let policy = match registry.written_policy_hash() {
            Some(_) => {
                let pinned = PinnedPolicy::of(&registry)?;
                let read = MemberRead {
                    root,
                    member: self.asset.asset,
                }
                .read(rpc)
                .await?;
                Some(AssetScreen {
                    sources: pinned.sources,
                    policy_hash: pinned.policy_hash,
                    asset: MemberOpening::from(&read.opening),
                    registry,
                })
            }
            None => None,
        };
        Ok(DepositRecords {
            root,
            escrowed,
            policy,
        })
    }

    /// The recipient's record under `root`, it must escrow the deposited key.
    async fn record(
        &self,
        rpc: &(impl AsyncRpc + AsyncRingIndexer + ?Sized),
        root: BoundRoot,
    ) -> Result<EscrowedRecord, RingError> {
        let read = MemberRead {
            root,
            member: self.owner_pk_hash,
        }
        .read(rpc)
        .await?;
        let escrowed = OwnerRead {
            owner: self.owner_pk_hash,
            read: &read,
        }
        .escrowed(&self.nullifier_pk)?;
        Ok(EscrowedRecord {
            opening: RecordOpeningRequest::present(escrowed.record, escrowed.path),
            ct_hash: escrowed.ct_hash()?,
        })
    }

    fn body<'a>(
        &self,
        records: Option<&'a DepositRecords>,
    ) -> Result<Box<DepositRequest<'a>>, RingError> {
        let record = records.and_then(|records| records.escrowed.as_ref());
        let policy = records.and_then(|records| records.policy.as_ref());
        let public_input_hash = DepositPublicInput {
            context_hash: &self.context_hash,
            anonymous: self.owner_key.is_some(),
            owner_utxo_hashes: &[self.owner_utxo_hash],
            ciphertexts: &self.encryption.ciphertexts,
            assets: &[self.asset],
            auditor_pk: self.auditor.as_bytes(),
            eph_pk: self.encryption.ephemeral_pk.as_bytes(),
            registry: records.map(|records| DepositRegistry {
                own_root: &records.root.root,
                key_escrow: self.key_escrow,
                policy_hash: policy.map(|policy| &policy.policy_hash),
            }),
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
            key_escrow: record.is_some(),
            member_registry_root: records.map_or([0; 32], |records| records.root.root),
            policy_hash: policy.map_or([0; 32], |policy| policy.policy_hash),
            assets: first(self.asset.asset),
            amounts: first(right_align(&self.asset.amount.to_be_bytes())),
            table: policy.map(|policy| PolicyTable {
                rules: &policy.registry.rules,
                sources: &policy.sources,
            }),
            asset_records: [policy.map(|policy| policy.asset.clone())],
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
