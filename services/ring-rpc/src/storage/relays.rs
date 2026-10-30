use sea_orm::{ConnectionTrait, DbErr, QueryResult, Statement, Value};
use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_message::VersionedMessage;
use solana_signature::Signature;
use spr_indexer_api::{Base64String, Hash, SerializablePubkey, SerializableSignature};
use zolana_ring_client::rpc::RelayId;
use zolana_ring_policy::Member;

use crate::{cosign::AssetFlow, relay_submit::CollectedSignature};

/// Holds no proof input.
#[derive(Clone)]
pub(crate) struct RelayRecord {
    pub message: VersionedMessage,
    pub signatures: Vec<CollectedSignature>,
    /// Signers the message still lacks.
    pub awaiting: Vec<Address>,
    /// Decided once `awaiting` is empty, an unsigned relay reserves no allowance.
    pub co_sign: Option<PendingCoSign>,
    /// Settled with the co-signer when the relay ends.
    pub co_signature: Option<Signature>,
    pub last_valid_block_height: u64,
    pub state: RelayState,
}

#[derive(Clone)]
pub(crate) struct PendingCoSign {
    pub signer: Address,
    pub ring: Address,
    pub sender: Member,
    pub flows: Vec<AssetFlow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(crate) enum RelayState {
    AwaitingSignature,
    /// Every signature collected, the send not yet recorded.
    Signed,
    Sent {
        signature: SerializableSignature,
    },
    Confirmed {
        signature: SerializableSignature,
        slot: u64,
    },
    Failed {
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayPhase {
    Pending,
    Confirmed,
    Failed,
}

pub(crate) struct RelayStore<'a, C> {
    db: &'a C,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredRelay {
    message: Base64String,
    signatures: Vec<StoredSignature>,
    awaiting: Vec<SerializablePubkey>,
    co_sign: Option<StoredCoSign>,
    co_signature: Option<SerializableSignature>,
    last_valid_block_height: u64,
    state: RelayState,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredCoSign {
    signer: SerializablePubkey,
    ring: SerializablePubkey,
    sender: Hash,
    flows: Vec<StoredFlow>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredFlow {
    asset: SerializablePubkey,
    transferred: u64,
    deposited: u64,
    withdrawn: u64,
}

#[derive(Serialize, Deserialize)]
struct StoredSignature {
    signer: SerializablePubkey,
    signature: SerializableSignature,
}

const PENDING: [&str; 3] = ["awaitingSignature", "signed", "sent"];
const CONFIRMED: &str = "confirmed";
const FAILED: &str = "failed";

impl RelayState {
    fn status(&self) -> &'static str {
        match self {
            Self::AwaitingSignature => PENDING[0],
            Self::Signed => PENDING[1],
            Self::Sent { .. } => PENDING[2],
            Self::Confirmed { .. } => CONFIRMED,
            Self::Failed { .. } => FAILED,
        }
    }
}

impl RelayPhase {
    pub(crate) fn of_status(status: &str) -> Result<Self, DbErr> {
        match status {
            CONFIRMED => Ok(Self::Confirmed),
            FAILED => Ok(Self::Failed),
            pending if PENDING.contains(&pending) => Ok(Self::Pending),
            _ => Err(corrupt("status")),
        }
    }
}

impl<'a, C: ConnectionTrait> RelayStore<'a, C> {
    pub fn new(db: &'a C) -> Self {
        Self { db }
    }

    pub async fn get(&self, id: &RelayId) -> Result<Option<RelayRecord>, DbErr> {
        let sql = "SELECT state FROM relay_relays WHERE relay_id=$1";
        let statement = self.statement(sql, vec![key(id)]);
        self.db
            .query_one(statement)
            .await?
            .map(|row| record(&row))
            .transpose()
    }

    /// `false` when the relay is stored already, the first record stays.
    pub async fn insert(&self, id: &RelayId, record: &RelayRecord) -> Result<bool, DbErr> {
        let sql = "INSERT INTO relay_relays(relay_id,status,state) VALUES($1,$2,$3) \
                   ON CONFLICT(relay_id) DO NOTHING";
        let values = vec![key(id), record.state.status().into(), state(record)?];
        let result = self.db.execute(self.statement(sql, values)).await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn update(&self, id: &RelayId, record: &RelayRecord) -> Result<(), DbErr> {
        let sql = "UPDATE relay_relays SET status=$2, state=$3 WHERE relay_id=$1";
        let values = vec![key(id), record.state.status().into(), state(record)?];
        self.db.execute(self.statement(sql, values)).await?;
        Ok(())
    }

    pub async fn pending(&self) -> Result<Vec<RelayId>, DbErr> {
        let sql = "SELECT relay_id FROM relay_relays WHERE status IN ($1,$2,$3)";
        let values = PENDING.map(Value::from).to_vec();
        self.db
            .query_all(self.statement(sql, values))
            .await?
            .iter()
            .map(|row| {
                let id: Vec<u8> = row.try_get("", "relay_id")?;
                let id: [u8; 32] = id.try_into().map_err(|_| corrupt("relay_id"))?;
                Ok(RelayId(id.into()))
            })
            .collect()
    }

    fn statement(&self, sql: &str, values: Vec<Value>) -> Statement {
        Statement::from_sql_and_values(self.db.get_database_backend(), sql, values)
    }
}

fn key(id: &RelayId) -> Value {
    id.0 .0.to_vec().into()
}

fn state(record: &RelayRecord) -> Result<Value, DbErr> {
    let stored = StoredRelay {
        message: record.message.serialize().into(),
        signatures: record
            .signatures
            .iter()
            .map(|collected| StoredSignature {
                signer: collected.signer.into(),
                signature: collected.signature.into(),
            })
            .collect(),
        awaiting: record.awaiting.iter().copied().map(Into::into).collect(),
        co_sign: record.co_sign.as_ref().map(|pending| StoredCoSign {
            signer: pending.signer.into(),
            ring: pending.ring.into(),
            sender: Hash(*pending.sender.as_bytes()),
            flows: pending
                .flows
                .iter()
                .map(|flow| StoredFlow {
                    asset: flow.asset.into(),
                    transferred: flow.transferred,
                    deposited: flow.deposited,
                    withdrawn: flow.withdrawn,
                })
                .collect(),
        }),
        co_signature: record.co_signature.map(Into::into),
        last_valid_block_height: record.last_valid_block_height,
        state: record.state.clone(),
    };
    serde_json::to_string(&stored)
        .map(Value::from)
        .map_err(|error| DbErr::Custom(error.to_string()))
}

fn record(row: &QueryResult) -> Result<RelayRecord, DbErr> {
    let state: String = row.try_get("", "state")?;
    let stored: StoredRelay = serde_json::from_str(&state).map_err(|_| corrupt("state"))?;
    Ok(RelayRecord {
        message: wincode::deserialize(&stored.message.0).map_err(|_| corrupt("message"))?,
        signatures: stored
            .signatures
            .into_iter()
            .map(|stored| CollectedSignature {
                signer: stored.signer.0,
                signature: stored.signature.0,
            })
            .collect(),
        awaiting: stored.awaiting.into_iter().map(|signer| signer.0).collect(),
        co_sign: stored.co_sign.map(pending_co_sign).transpose()?,
        co_signature: stored.co_signature.map(|signature| signature.0),
        last_valid_block_height: stored.last_valid_block_height,
        state: stored.state,
    })
}

fn pending_co_sign(stored: StoredCoSign) -> Result<PendingCoSign, DbErr> {
    Ok(PendingCoSign {
        signer: stored.signer.0,
        ring: stored.ring.0,
        sender: Member::from_bytes(stored.sender.0).map_err(|_| corrupt("co_sign"))?,
        flows: stored
            .flows
            .into_iter()
            .map(|flow| AssetFlow {
                asset: flow.asset.0,
                transferred: flow.transferred,
                deposited: flow.deposited,
                withdrawn: flow.withdrawn,
            })
            .collect(),
    })
}

fn corrupt(column: &str) -> DbErr {
    DbErr::Custom(format!("relay_relays {column} is corrupt"))
}
