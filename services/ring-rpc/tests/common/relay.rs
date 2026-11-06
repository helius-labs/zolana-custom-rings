//! Relay fakes and the sealed transfer a wallet leaves for Ring RPC.

use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Mutex,
};

use async_trait::async_trait;
use solana_address::Address;
use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use spr_client::{ClientError, ComputeBudgetConfig};
use spr_event::MessageData;
use spr_instruction::instruction::{
    TransactInterfaceTransferAccounts, TransactSolTransferAccounts,
};
use spr_interface::{
    instruction::instruction_data::transact::{OwnerTag, TransactOutput},
    MAX_OUTPUTS,
};
use spr_keypair::{NullifierKey, ShieldedKeypair, SigningKey, ViewingKey, X25519Keypair};
use spr_transaction::{
    instructions::transact::{ExternalData, SettlementTransfer},
    utxo::SppProofInputUtxo,
    Data, Mint, SppProofOutputUtxo, Utxo,
};
use zolana_ring_client::rpc::{
    PrepareRelayRequest, ProofInputBytes, RelayEnrollInputs, RelayIntent, RelayProofInputs,
    RelayQuote, RelayRail,
};
use zolana_ring_rpc::{
    ChainOutcome, ChainSubmit, DelegateSeal, LatestBlockhash, ProvenRelay, RelayError,
    RelayParties, RelayPayload, RelayProofRequest, RelayProver, RingRpcError,
};
use zolana_ring_transaction::AnonymousPlan;

pub const SLOT: u64 = 1_000;
pub const RENT_LAMPORTS: u64 = 1_000;
pub const LAST_VALID_BLOCK_HEIGHT: u64 = 500;
/// An input tree and an output tree, each under the default schedule.
pub const TREE_FEES: u64 = 2 * spr_interface::state::DEFAULT_FEE_PER_TREE_LAMPORTS;
const OWNER_SEED: [u8; 32] = [5; 32];

#[derive(Default)]
pub struct RecordingProver {
    pub requests: Mutex<Vec<(Address, Option<[u8; 64]>)>>,
    /// Named as signers on every proven transfer, absent reads the relay's parties.
    pub co_signers: Option<Vec<Address>>,
    /// The next proven transfer's data, a frame past one transaction.
    pub frame: Mutex<Option<Vec<u8>>>,
    pub refuse_enrollment: AtomicBool,
}

#[async_trait]
impl RelayProver for RecordingProver {
    async fn prove(&self, request: RelayProofRequest<'_>) -> Result<ProvenRelay, RingRpcError> {
        self.requests
            .lock()
            .expect("requests")
            .push((request.parties.fee_payer, request.owner_signature));
        let (signers, data) = match request.payload {
            RelayPayload::Transfer(proof_inputs) => (
                match proof_inputs.rail {
                    RelayRail::Delegate { delegate, .. } => vec![delegate],
                    _ => Vec::new(),
                },
                proof_inputs.blinding_seed.to_vec(),
            ),
            RelayPayload::Deposit(deposit) => (deposit.deposit_funders().collect(), vec![1, 2, 3]),
            RelayPayload::Merge(_) => (Vec::new(), vec![1, 2, 3]),
            RelayPayload::Enroll(_) => panic!("the relay builds an enrollment itself"),
        };
        let co_signers = self
            .co_signers
            .clone()
            .unwrap_or_else(|| request.parties.co_signers.clone());
        let accounts = core::iter::once(AccountMeta::new(request.parties.fee_payer, true))
            .chain(
                signers
                    .iter()
                    .chain(&co_signers)
                    .map(|signer| AccountMeta::new_readonly(*signer, true)),
            )
            .collect();
        let data = self.frame.lock().expect("frame").take().unwrap_or(data);
        Ok(ProvenRelay {
            instruction: Instruction {
                program_id: request.ring,
                accounts,
                data,
            },
            budget: ComputeBudgetConfig::new(400_000),
            co_signers,
            signers,
            tree_fees: TREE_FEES,
        })
    }

    async fn seal_delegate(
        &self,
        _seal: DelegateSeal<'_>,
        _parties: RelayParties,
    ) -> Result<RelayProofInputs, RingRpcError> {
        unreachable!("the wallet seals its own transfer")
    }

    async fn check_enrollment(&self, _enrollment: &RelayEnrollInputs) -> Result<(), RingRpcError> {
        match self.refuse_enrollment.load(Ordering::Relaxed) {
            true => Err(RelayError::InvalidEnrollment.into()),
            false => Ok(()),
        }
    }
}

/// Every sent transaction lands, a send past `LAST_VALID_BLOCK_HEIGHT` is refused.
pub struct RecordingChain {
    pub sent: Mutex<Vec<VersionedTransaction>>,
    pub height: AtomicU64,
    /// The next send lands and its reply is lost.
    pub reply_lost: AtomicBool,
    /// The next send is refused at preflight and forwards nothing.
    pub refuse_next: AtomicBool,
    /// Answers every outcome lookup, `None` reads as a sent transaction landing.
    pub outcome: Mutex<Option<Option<ChainOutcome>>>,
    pub slot: AtomicU64,
    pub accounts: Mutex<Vec<Address>>,
    /// Live accounts that hold data, an enrolled owner's tracking authorization.
    pub filled: Mutex<Vec<Address>>,
    pub simulation_refusal: Mutex<Option<String>>,
}

impl Default for RecordingChain {
    fn default() -> Self {
        Self {
            sent: Mutex::default(),
            height: AtomicU64::new(400),
            reply_lost: AtomicBool::new(false),
            refuse_next: AtomicBool::new(false),
            outcome: Mutex::new(None),
            slot: AtomicU64::new(SLOT),
            accounts: Mutex::default(),
            filled: Mutex::default(),
            simulation_refusal: Mutex::default(),
        }
    }
}

impl RecordingChain {
    pub fn sent(&self) -> Vec<VersionedTransaction> {
        self.sent.lock().expect("sent").clone()
    }
}

#[async_trait]
impl ChainSubmit for RecordingChain {
    async fn simulate(
        &self,
        _message: &solana_message::VersionedMessage,
    ) -> Result<zolana_ring_rpc::Simulation, RingRpcError> {
        Ok(
            match self.simulation_refusal.lock().expect("refusal").clone() {
                Some(reason) => zolana_ring_rpc::Simulation::Refused { reason },
                None => zolana_ring_rpc::Simulation::Passed,
            },
        )
    }

    async fn slot(&self) -> Result<u64, RingRpcError> {
        Ok(self.slot.load(Ordering::Relaxed))
    }

    async fn account_data(&self, address: Address) -> Result<Option<Vec<u8>>, RingRpcError> {
        if self.filled.lock().expect("filled").contains(&address) {
            return Ok(Some(vec![1]));
        }
        Ok(self
            .accounts
            .lock()
            .expect("accounts")
            .contains(&address)
            .then(Vec::new))
    }

    async fn rent_exempt_lamports(&self, _data_len: usize) -> Result<u64, RingRpcError> {
        Ok(RENT_LAMPORTS)
    }

    async fn latest_blockhash(&self) -> Result<LatestBlockhash, RingRpcError> {
        Ok((Hash::new_from_array([8; 32]), LAST_VALID_BLOCK_HEIGHT).into())
    }

    async fn block_height(&self) -> Result<u64, RingRpcError> {
        Ok(self.height.load(Ordering::Relaxed))
    }

    async fn send(&self, transaction: &VersionedTransaction) -> Result<(), RingRpcError> {
        if self.refuse_next.swap(false, Ordering::Relaxed) {
            return Err(RelayError::SendRefused {
                reason: "preflight refused".to_owned(),
            }
            .into());
        }
        if self.height.load(Ordering::Relaxed) > LAST_VALID_BLOCK_HEIGHT {
            return Err(RelayError::SendRefused {
                reason: "Blockhash not found".to_owned(),
            }
            .into());
        }
        self.sent.lock().expect("sent").push(transaction.clone());
        match self.reply_lost.swap(false, Ordering::Relaxed) {
            true => Err(RingRpcError::Upstream(ClientError::Rpc(
                "the send reply was lost".to_owned(),
            ))),
            false => Ok(()),
        }
    }

    async fn outcome(&self, signature: Signature) -> Result<Option<ChainOutcome>, RingRpcError> {
        if let Some(outcome) = self.outcome.lock().expect("outcome").clone() {
            return Ok(outcome);
        }
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
        plan: Box::new(AnonymousPlan::from_parts(
            vec![owner().viewing_pubkey()],
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
        list_salts: Vec::new(),
        co_owners: Vec::new(),
        approval_blinder: None,
        wide_owners: false,
    }
}

/// A SOL deposit to the owner, the depositor signs the request and later its funding.
pub fn deposit_request(
    quote: RelayQuote,
    ring: Address,
    depositor: &solana_keypair::Keypair,
    amount: u64,
) -> PrepareRelayRequest {
    let mut deposit = proof_inputs(ring, RelayRail::Deposit { plan: None });
    deposit.inputs = vec![SppProofInputUtxo::dummy_with_blinding([47; 32], 4).expect("dummy")];
    deposit.outputs[0].amount = amount;
    deposit.external_data.interface_transfers = vec![SettlementTransfer::Sol {
        is_deposit: true,
        amount,
        user_sol_account: depositor.pubkey(),
    }];
    deposit.interface_transfer_accounts = vec![TransactInterfaceTransferAccounts::Sol(
        TransactSolTransferAccounts {
            recipient: depositor.pubkey(),
        },
    )];
    let proof_inputs = ProofInputBytes::new(deposit.encode().expect("encode"));
    let depositor_signature = depositor
        .sign_message(&proof_inputs.deposit_request_digest())
        .into();
    PrepareRelayRequest {
        ring: ring.into(),
        quote,
        intent: RelayIntent::Deposit {
            proof_inputs,
            depositor_signature,
        },
        co_signers: Vec::new(),
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
        co_signers: Vec::new(),
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
