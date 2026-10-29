//! Relay fakes and the sealed transfer a wallet leaves for Ring RPC.

use std::sync::Mutex;

use async_trait::async_trait;
use custom_ring_interface::cosign::CoSignDemand;
use solana_address::Address;
use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use spr_client::ComputeBudgetConfig;
use spr_event::MessageData;
use spr_interface::{
    instruction::instruction_data::transact::{OwnerTag, TransactOutput},
    MAX_OUTPUTS,
};
use spr_keypair::{NullifierKey, ShieldedKeypair, SigningKey, ViewingKey, X25519Keypair};
use spr_transaction::{
    instructions::transact::ExternalData, utxo::SppProofInputUtxo, Data, Mint, SppProofOutputUtxo,
    Utxo,
};
use zolana_ring_client::rpc::{
    PrepareRelayRequest, ProofInputBytes, RelayIntent, RelayProofInputs, RelayQuote, RelayRail,
};
use zolana_ring_rpc::{
    ChainOutcome, DelegateSeal, ProvenRelay, RelayChain, RelayParties, RelayPayload,
    RelayProofRequest, RelayProver, RingRpcError,
};
use zolana_ring_transaction::{AnonymousPlan, TaggedPayment};

pub const SLOT: u64 = 1_000;
const OWNER_SEED: [u8; 32] = [5; 32];

#[derive(Default)]
pub struct RecordingProver {
    pub requests: Mutex<Vec<(Address, Option<[u8; 64]>)>>,
    /// Named as a signer on every proven transfer.
    pub co_signer: Option<Address>,
}

#[async_trait]
impl RelayProver for RecordingProver {
    async fn prove(&self, request: RelayProofRequest<'_>) -> Result<ProvenRelay, RingRpcError> {
        self.requests
            .lock()
            .expect("requests")
            .push((request.fee_payer, request.owner_signature));
        let (signers, data) = match request.payload {
            RelayPayload::Transfer(proof_inputs) => (
                match proof_inputs.rail {
                    RelayRail::Delegate { delegate } => vec![delegate],
                    _ => Vec::new(),
                },
                proof_inputs.blinding_seed.to_vec(),
            ),
            RelayPayload::Deposit(deposit) => (vec![deposit.depositor], vec![1, 2, 3]),
            RelayPayload::Merge(_) => (Vec::new(), vec![1, 2, 3]),
        };
        let accounts = core::iter::once(AccountMeta::new(request.fee_payer, true))
            .chain(
                signers
                    .iter()
                    .chain(&self.co_signer)
                    .map(|signer| AccountMeta::new_readonly(*signer, true)),
            )
            .collect();
        Ok(ProvenRelay {
            instruction: Instruction {
                program_id: request.ring,
                accounts,
                data,
            },
            budget: ComputeBudgetConfig::new(400_000),
            co_signer: self.co_signer,
            co_sign_demand: CoSignDemand::transact(false, &[]),
            signers,
        })
    }

    async fn seal_delegate(
        &self,
        _seal: DelegateSeal<'_>,
        _parties: RelayParties,
    ) -> Result<RelayProofInputs, RingRpcError> {
        unreachable!("the wallet seals its own transfer")
    }
}

#[derive(Default)]
pub struct RecordingChain {
    pub sent: Mutex<Vec<VersionedTransaction>>,
}

impl RecordingChain {
    pub fn sent(&self) -> Vec<VersionedTransaction> {
        self.sent.lock().expect("sent").clone()
    }
}

#[async_trait]
impl RelayChain for RecordingChain {
    async fn slot(&self) -> Result<u64, RingRpcError> {
        Ok(SLOT)
    }

    async fn latest_blockhash(&self) -> Result<(Hash, u64), RingRpcError> {
        Ok((Hash::new_from_array([8; 32]), 500))
    }

    async fn block_height(&self) -> Result<u64, RingRpcError> {
        Ok(400)
    }

    async fn send(&self, transaction: &VersionedTransaction) -> Result<(), RingRpcError> {
        self.sent.lock().expect("sent").push(transaction.clone());
        Ok(())
    }

    async fn outcome(&self, signature: Signature) -> Result<Option<ChainOutcome>, RingRpcError> {
        let sent = self.sent.lock().expect("sent");
        Ok(sent
            .iter()
            .any(|transaction| transaction.signatures[0] == signature)
            .then_some(ChainOutcome::Confirmed { slot: SLOT + 1 }))
    }
}

pub fn owner() -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&OWNER_SEED)).expect("owner")
}

pub fn owner_wallet() -> solana_keypair::Keypair {
    solana_keypair::Keypair::new_from_array(OWNER_SEED)
}

pub fn anonymous_rail() -> RelayRail {
    RelayRail::Anonymous {
        plan: Box::new(AnonymousPlan::from_tags(
            [23; 32],
            vec![TaggedPayment {
                recipient: owner().viewing_pubkey(),
                tag: [24; 32],
            }],
            [[25; 32]; MAX_OUTPUTS],
        )),
        exit_token_owner: None,
    }
}

/// One ring UTXO spent back to the sender, the outputs sealed as a wallet would leave them.
pub fn proof_inputs(ring: Address, rail: RelayRail) -> RelayProofInputs {
    let owner = owner();
    let sender = owner.shielded_address().expect("address");
    let utxo = Utxo {
        owner: sender.signing_pubkey,
        asset: Mint::SOL,
        amount: 900,
        blinding: [11; 32],
        ring_program_id: Some(ring),
        data: Data::default(),
    };
    let utxo_hash = utxo
        .hash(&sender.nullifier_pubkey, &[0; 32], &[0; 32], 4)
        .expect("hash");
    let spend = SppProofInputUtxo {
        address: false,
        nullifier: owner
            .nullifier_key
            .nullifier(&utxo_hash, &utxo.blinding)
            .expect("nullifier"),
        utxo,
        nullifier_pubkey: sender.nullifier_pubkey,
        utxo_hash,
        data_hash: None,
        ring_data_hash: None,
        tree_id: 4,
        leaf_index: 17,
        cache_slot: None,
        compact: false,
    };
    let tx_viewing_key = ViewingKey::from_secret_key(X25519Keypair::from_bytes(&[13; 32]));
    RelayProofInputs {
        rail,
        ring_program_id: ring,
        nullifier_key: NullifierKey::from_secret(*owner.nullifier_key.secret()),
        sender,
        external_data: ExternalData::new(
            *tx_viewing_key.pubkey().as_bytes(),
            [15; 16],
            vec![TransactOutput {
                utxo_hash: [16; 32],
                owner_tag: OwnerTag::Inline([17; 32]),
                data: Some(vec![18, 19]),
            }],
            vec![[20; 32]],
            vec![MessageData {
                view_tag: [21; 32],
                data: vec![22],
            }],
        ),
        tx_viewing_key,
        audit_ephemeral_key: zeroize::Zeroizing::new([26; 32]),
        inputs: vec![spend],
        outputs: vec![SppProofOutputUtxo {
            asset: Mint::SOL,
            amount: 900,
            blinding: [12; 32],
            ring_program_id: Some(ring),
            owner_address: Some(sender),
            ..SppProofOutputUtxo::default()
        }],
        interface_transfer_accounts: Vec::new(),
        blinding_seed: [28; 32],
        output_tree_id: 4,
    }
}

/// The owner signs `SppProofInputs::message_hash` before the relay proves.
pub fn signed_request(quote: RelayQuote, proof_inputs: &RelayProofInputs) -> PrepareRelayRequest {
    let digest = proof_inputs
        .spp_proof_inputs(quote.fee_payer.0)
        .message_hash()
        .expect("message hash");
    let owner_signature = owner_wallet().sign_message(&digest).into();
    let encoded = ProofInputBytes::new(proof_inputs.encode().expect("encode"));
    PrepareRelayRequest {
        ring: proof_inputs.ring_program_id.into(),
        quote,
        intent: match proof_inputs.rail {
            RelayRail::Anonymous { .. } => RelayIntent::Anonymous {
                proof_inputs: encoded,
                owner_signature,
                token_account_setup: Vec::new(),
            },
            _ => RelayIntent::Confidential {
                proof_inputs: encoded,
                owner_signature,
                token_account_setup: Vec::new(),
            },
        },
    }
}

pub fn signers_verify(transaction: &VersionedTransaction) -> bool {
    let message = transaction.message.serialize();
    transaction
        .signatures
        .iter()
        .zip(transaction.message.static_account_keys())
        .all(|(signature, signer)| signature.verify(signer.as_ref(), &message))
}
