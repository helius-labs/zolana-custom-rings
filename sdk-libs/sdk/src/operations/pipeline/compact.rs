//! The compact transact data a proven transfer owns, and its instruction.

use custom_ring_interface::{
    storage::Revision, tag, AnonymousProofData, CustomRingProof, InProofOwner, InputTrees,
    PlainGroth16Proof, PolicyProof, PolicyRecipients, RingOutput, RingPolicy, RingRail,
    RingTransactData, SenderBundle, AUDIT_CIPHERTEXT_LEN, RING_DELIVERED_BODY_LEN,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use spr_interface::instruction::{InterfaceTransfer, TransactProof};
use spr_program::instruction::{
    RingAuthorityTransact, RingTransact, TransactInterfaceTransferAccounts,
};

use crate::{CustomRing, RingError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum OwnedOutput {
    Delivered {
        hash: [u8; 32],
        u: [u8; 32],
        body: [u8; RING_DELIVERED_BODY_LEN],
    },
    Owned {
        hash: [u8; 32],
        owner: [u8; 32],
        u: [u8; 32],
        body: [u8; RING_DELIVERED_BODY_LEN],
    },
    Anonymous {
        hash: [u8; 32],
        tag: [u8; 32],
        body: Option<Vec<u8>>,
    },
    Exit {
        hash: [u8; 32],
        owner_tag: [u8; 32],
        payload: Vec<u8>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OwnedSenderBundle {
    pub tag: [u8; 32],
    pub body: Vec<u8>,
}

impl OwnedSenderBundle {
    pub fn of(sender: SenderBundle<'_>) -> Self {
        Self {
            tag: *sender.tag,
            body: sender.body.to_vec(),
        }
    }

    pub fn view(&self) -> SenderBundle<'_> {
        SenderBundle {
            tag: &self.tag,
            body: &self.body,
        }
    }
}

impl OwnedOutput {
    pub fn of(output: RingOutput<'_>) -> Self {
        match output {
            RingOutput::Delivered { hash, u, body } => Self::Delivered {
                hash: *hash,
                u: *u,
                body: *body,
            },
            RingOutput::Owned {
                hash,
                owner,
                u,
                body,
            } => Self::Owned {
                hash: *hash,
                owner: *owner,
                u: *u,
                body: *body,
            },
            RingOutput::Anonymous { hash, tag, body } => Self::Anonymous {
                hash: *hash,
                tag: *tag,
                body: body.map(<[u8]>::to_vec),
            },
            RingOutput::Exit {
                hash,
                owner_tag,
                payload,
            } => Self::Exit {
                hash: *hash,
                owner_tag: *owner_tag,
                payload: payload.to_vec(),
            },
        }
    }

    pub fn view(&self) -> RingOutput<'_> {
        match self {
            Self::Delivered { hash, u, body } => RingOutput::Delivered { hash, u, body },
            Self::Owned {
                hash,
                owner,
                u,
                body,
            } => RingOutput::Owned {
                hash,
                owner,
                u,
                body,
            },
            Self::Anonymous { hash, tag, body } => RingOutput::Anonymous {
                hash,
                tag,
                body: body.as_deref(),
            },
            Self::Exit {
                hash,
                owner_tag,
                payload,
            } => RingOutput::Exit {
                hash,
                owner_tag,
                payload,
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OwnedPolicyProof {
    pub spl_withdrawal_owners: Vec<[u8; 32]>,
    pub proof: CustomRingProof,
    pub own_revision: Revision,
    pub curator_revision: Option<Revision>,
    pub sender_commitment: Option<[u8; 32]>,
    pub recipients: OwnedRecipients,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum OwnedRecipients {
    Hidden,
    Framed(Vec<[u8; 32]>),
    Published { dummies: u64 },
}

impl OwnedRecipients {
    fn view(&self) -> PolicyRecipients<'_> {
        match self {
            Self::Hidden => PolicyRecipients::Hidden,
            Self::Framed(recipients) => PolicyRecipients::Framed(recipients),
            Self::Published { dummies } => PolicyRecipients::Published { dummies: *dummies },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OwnedInProofOwner {
    pub owner: [u8; 32],
    pub commitment: [u8; 32],
    pub commitment_pok: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OwnedAnonymousProofData {
    pub commitment: [u8; 32],
    pub commitment_pok: [u8; 32],
    pub default_owner_tag: Option<[u8; 32]>,
}

/// [`RingTransactData`] with every borrowed part owned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TransactParts {
    pub rail: RingRail,
    pub n_in: u8,
    pub n_out: u8,
    pub audit_proof: CustomRingProof,
    pub policy: Option<OwnedPolicyProof>,
    pub withdrawal_exemption: Option<custom_ring_interface::WithdrawalExemptionProof>,
    pub approval_required: bool,
    pub expiry_unix_ts: u32,
    pub tx_viewing_u: [u8; 32],
    pub salt: [u8; 16],
    pub interface_transfers: Vec<InterfaceTransfer>,
    pub key_escrow: bool,
    pub full_openings: bool,
    pub outputs: Vec<OwnedOutput>,
    pub sender: Option<OwnedSenderBundle>,
    pub eph_u: [u8; 32],
    pub sealed: [u8; AUDIT_CIPHERTEXT_LEN],
    pub disclosure: Vec<[u8; 32]>,
    pub private_tx_hash: [u8; 32],
    pub anonymous: Option<OwnedAnonymousProofData>,
    pub in_proof_owner: Option<OwnedInProofOwner>,
    pub spp_proof: PlainGroth16Proof,
    pub nullifiers: Vec<[u8; 32]>,
    pub input_trees: InputTrees,
}

impl TransactParts {
    pub fn data(&self) -> RingTransactData<'_> {
        RingTransactData {
            rail: self.rail,
            n_in: self.n_in,
            n_out: self.n_out,
            audit_proof: &self.audit_proof,
            policy: self.policy.as_ref().map(|policy| PolicyProof {
                spl_withdrawal_owners: &policy.spl_withdrawal_owners,
                proof: &policy.proof,
                own_revision: policy.own_revision,
                curator_revision: policy.curator_revision,
                sender_commitment: policy.sender_commitment.as_ref(),
                recipients: policy.recipients.view(),
            }),
            withdrawal_exemption: self.withdrawal_exemption.as_ref(),
            approval_required: self.approval_required,
            expiry_unix_ts: self.expiry_unix_ts,
            tx_viewing_u: &self.tx_viewing_u,
            salt: &self.salt,
            interface_transfers: self.interface_transfers.clone(),
            key_escrow: self.key_escrow,
            full_openings: self.full_openings,
            outputs: self.outputs.iter().map(OwnedOutput::view).collect(),
            sender: self.sender.as_ref().map(OwnedSenderBundle::view),
            eph_u: &self.eph_u,
            sealed: &self.sealed,
            disclosure: &self.disclosure,
            private_tx_hash: &self.private_tx_hash,
            anonymous: self.anonymous.as_ref().map(|anonymous| AnonymousProofData {
                commitment: &anonymous.commitment,
                commitment_pok: &anonymous.commitment_pok,
                default_owner_tag: anonymous.default_owner_tag.as_ref(),
            }),
            in_proof_owner: self.in_proof_owner.as_ref().map(|owner| InProofOwner {
                owner: &owner.owner,
                commitment: &owner.commitment,
                commitment_pok: &owner.commitment_pok,
            }),
            spp_proof: &self.spp_proof,
            nullifiers: &self.nullifiers,
            input_trees: self.input_trees,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TransactAccounts {
    pub payer: Address,
    /// One per tree context, in the data's order.
    pub input_trees: Vec<Address>,
    pub output_tree: Address,
    /// Only the confidential rail names owner signers.
    pub owner_signers: Vec<Address>,
    pub interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    pub co_signer: Option<Address>,
    pub delegate: Option<Address>,
}

impl TransactAccounts {
    /// The ring prefix, then SPP's own list, the data's tag by its rail.
    pub fn instruction(
        &self,
        ring: CustomRing,
        config: &RingPolicy,
        parts: &TransactParts,
    ) -> Result<Instruction, RingError> {
        let data = parts.data();
        let expanded = data.transact_ix_data(config, TransactProof::zeroed())?;
        let spp = match parts.rail {
            RingRail::Delegate => {
                RingAuthorityTransact {
                    payer: self.payer,
                    input_trees: self.input_trees.clone(),
                    output_tree: self.output_tree,
                    ring_program_id: ring.program_id(),
                    interface_transfer_accounts: Vec::new(),
                    data: expanded,
                }
                .instruction()
                .accounts
            }
            RingRail::Confidential | RingRail::Anonymous => {
                RingTransact {
                    payer: self.payer,
                    input_trees: self.input_trees.clone(),
                    output_tree: self.output_tree,
                    ring_program_id: ring.program_id(),
                    owner_signers: self.owner_signers.clone(),
                    interface_transfer_accounts: self.interface_transfer_accounts.clone(),
                    data: expanded,
                }
                .instruction()
                .accounts
            }
        };
        let mut accounts = vec![AccountMeta::new_readonly(ring.policy_pda(), false)];
        accounts.extend(
            self.co_signer
                .into_iter()
                .flat_map(|co_signer| ring.co_signer_metas(co_signer)),
        );
        accounts.extend(
            self.delegate
                .map(|delegate| AccountMeta::new_readonly(delegate, true)),
        );
        accounts.extend(spp);
        let mut bytes = vec![match parts.rail {
            RingRail::Delegate => tag::AUTHORITY_TRANSFER,
            RingRail::Confidential | RingRail::Anonymous => tag::TRANSFER,
        }];
        bytes.extend(data.encode()?);
        Ok(Instruction {
            program_id: ring.program_id(),
            accounts,
            data: bytes,
        })
    }
}
