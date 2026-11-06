//! A ring's durable projection, what its auditor opened and the frames it could not read.
//!
//! The lease holder writes it, each commit fenced by the lease. Every replica reads it from one
//! snapshot, so a load never pairs a newer checkpoint with an older spend. Read after
//! `storage/projection_lease.rs`.

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    Aes256Gcm, Nonce,
};
use custom_ring_interface::REGISTER_KEY_CIPHERTEXT_LEN;
use sea_orm::{
    AccessMode, ConnectionTrait, DatabaseBackend, DatabaseConnection, DatabaseTransaction, DbErr,
    IsolationLevel, QueryResult, Statement, TransactionTrait, Value,
};
use sha2::Sha256;
use solana_address::Address;
use solana_signature::Signature;
use spr_indexer_api::{Context, PaginationToken};
use spr_keypair::X25519Keypair;
use zolana_ring_client::{history::HistoryPosition, KnownUtxo, UtxoOwner};

use crate::{
    frame_repairs::RepairAttempt,
    hub::Clock,
    owner_notes::{IndexTags, OwnerNoteWrites},
    projection_lease::ProjectionLease,
    spend_machine::{SpendRow, SpendState},
    tracking::{HeldEnrollment, TrackingCursor},
    utxos::{CreatedIn, LateOwner, PageDelta, StoredUtxo, MAX_LATE_OWNERS},
};

const NOTE_SEAL_INFO: &[u8] = b"zolana/ring-rpc-note-seal";
const NONCE_LEN: usize = 12;
const NOTE_BODY_LEN: usize =
    32 + 1 + 32 + 32 + 1 + 32 + 8 + 32 + 32 + 32 + 2 + 1 + 8 + 64 + 2 + 4 + 8 + 1 + 32;

/// Keys the note rows of one ring, a stolen database opens no note.
pub(crate) struct NoteSeal {
    cipher: Aes256Gcm,
    ring: Address,
    pub(crate) tags: IndexTags,
}

/// The durable resume point, the history slot moves only at a terminal page.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Checkpoint {
    pub position: HistoryPosition,
    pub through: Context,
}

/// The repair schedule lists only frames that failed a repair.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct LoadedProjection {
    pub spends: LoadedSpends,
    pub repairs: Vec<(CreatedIn, RepairAttempt)>,
    pub enrollments: Vec<HeldEnrollment>,
    pub tracking_cursor: TrackingCursor,
    /// The snapshot's revision, every row the load read was written at or below it.
    pub revision: i64,
}

/// The note and spend rows a load reads beside the unread frames, faults and checkpoints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HistoryScope {
    /// Every row, for a mirror that holds the whole projection.
    Everything,
    /// No row, a bounded cache fills from lookups.
    Cold,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct LoadedSpends {
    pub checkpoint: Checkpoint,
    pub notes: Vec<([u8; 32], StoredUtxo)>,
    pub rows: Vec<SpendRow>,
    pub unread: Vec<CreatedIn>,
    pub faults: Vec<SpendRow>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CommittedPage {
    pub revision: i64,
    pub first_unread: Option<CreatedIn>,
}

pub(crate) async fn first_unread(
    connection: &impl ConnectionTrait,
    ring: Address,
) -> Result<Option<CreatedIn>, DbErr> {
    connection
        .query_one(Statement::from_sql_and_values(
            connection.get_database_backend(),
            "SELECT slot,tx_signature,event_index FROM spend_unread_frames WHERE ring=$1 \
             ORDER BY slot,tx_signature,event_index LIMIT 1",
            vec![Value::from(ring.as_ref().to_vec())],
        ))
        .await?
        .as_ref()
        .map(read_frame)
        .transpose()
}

impl NoteSeal {
    pub(crate) fn derive(auditor: &X25519Keypair, ring: Address) -> Result<Self, DbErr> {
        let unusable = || DbErr::Custom("note seal key is unusable".into());
        let mut key = zeroize::Zeroizing::new([0u8; 32]);
        hkdf::Hkdf::<Sha256>::new(None, auditor.secret_bytes().as_slice())
            .expand(NOTE_SEAL_INFO, key.as_mut_slice())
            .map_err(|_| unusable())?;
        Ok(Self {
            cipher: Aes256Gcm::new_from_slice(key.as_slice()).map_err(|_| unusable())?,
            ring,
            tags: IndexTags::derive(auditor, ring),
        })
    }

    /// The ring and the row key bind the body, a row moved to another key fails to open.
    pub(crate) fn seal(&self, row_key: &[u8; 32], body: &[u8]) -> Result<Vec<u8>, DbErr> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let aad = [self.ring.as_ref(), row_key.as_slice()].concat();
        let sealed = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: body,
                    aad: &aad,
                },
            )
            .map_err(|_| DbErr::Custom("note row failed to seal".into()))?;
        Ok([nonce.as_slice(), &sealed].concat())
    }

    pub(crate) fn open(&self, row_key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, DbErr> {
        let refused = || DbErr::Custom("note row does not open under the auditor key".into());
        let (nonce, ciphertext) = sealed.split_at_checked(NONCE_LEN).ok_or_else(refused)?;
        let aad = [self.ring.as_ref(), row_key.as_slice()].concat();
        self.cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| refused())
    }
}

/// The one layout of a sealed note.
pub(crate) fn note_body(note: &StoredUtxo) -> Vec<u8> {
    let utxo = &note.utxo;
    let UtxoOwner::Keyed { nullifier_pk } = utxo.owner;
    let mint = utxo.mint.map_or([0; 32], |mint| mint.to_bytes());
    let nullifier = note.nullifier.unwrap_or_default();
    [
        utxo.owner_key.as_slice(),
        &[0],
        &nullifier_pk,
        &utxo.asset,
        &[u8::from(utxo.mint.is_some())],
        &mint,
        &utxo.amount.to_be_bytes(),
        &utxo.blinding,
        &utxo.data_hash,
        &utxo.ring_data_hash,
        &utxo.tree_id.to_be_bytes(),
        &[u8::from(note.ring_note)],
        &note.created_in.slot.to_be_bytes(),
        note.created_in.tx_signature.as_ref(),
        &note.created_in.event_index.to_be_bytes(),
        &note.slot_index.to_be_bytes(),
        &note.leaf_index.to_be_bytes(),
        &[u8::from(note.nullifier.is_some())],
        &nullifier,
    ]
    .concat()
}

pub(crate) fn note_from_body(body: &[u8]) -> Result<StoredUtxo, DbErr> {
    let malformed = || DbErr::Custom("note body has another layout".into());
    if body.len() != NOTE_BODY_LEN {
        return Err(malformed());
    }
    let mut rest = body;
    let mut take = |len: usize| {
        let (taken, tail) = rest.split_at(len);
        rest = tail;
        taken
    };
    fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
        let mut out = [0; N];
        out.copy_from_slice(bytes);
        out
    }
    let owner_key = array(take(32));
    let owner_kind = take(1)[0];
    let owner_field: [u8; 32] = array(take(32));
    let owner = match owner_kind {
        0 => UtxoOwner::Keyed {
            nullifier_pk: owner_field,
        },
        _ => return Err(malformed()),
    };
    let asset = array(take(32));
    let has_mint = take(1)[0] == 1;
    let mint_bytes: [u8; 32] = array(take(32));
    let amount = u64::from_be_bytes(array(take(8)));
    let blinding = array(take(32));
    let data_hash = array(take(32));
    let ring_data_hash = array(take(32));
    let tree_id = u16::from_be_bytes(array(take(2)));
    let ring_note = take(1)[0] == 1;
    let slot = u64::from_be_bytes(array(take(8)));
    let tx_signature = Signature::from(array::<64>(take(64)));
    let event_index = u16::from_be_bytes(array(take(2)));
    let slot_index = u32::from_be_bytes(array(take(4)));
    let leaf_index = u64::from_be_bytes(array(take(8)));
    let has_nullifier = take(1)[0] == 1;
    let nullifier: [u8; 32] = array(take(32));
    Ok(StoredUtxo {
        utxo: KnownUtxo {
            owner_key,
            owner,
            asset,
            mint: has_mint.then(|| Address::new_from_array(mint_bytes)),
            amount,
            blinding,
            data_hash,
            ring_data_hash,
            tree_id,
        },
        created_in: CreatedIn {
            slot,
            tx_signature,
            event_index,
        },
        slot_index,
        leaf_index,
        ring_note,
        nullifier: has_nullifier.then_some(nullifier),
    })
}

pub(crate) fn state_name(state: SpendState) -> &'static str {
    match state {
        SpendState::Observed => "observed",
        SpendState::Padding => "padding",
        SpendState::Address => "address",
        SpendState::External => "external",
        SpendState::Resolved { .. } => "resolved",
        SpendState::UnresolvedReal => "unresolved",
    }
}

fn state_of(name: &str, link: Option<[u8; 32]>) -> Result<SpendState, DbErr> {
    match (name, link) {
        ("observed", None) => Ok(SpendState::Observed),
        ("padding", None) => Ok(SpendState::Padding),
        ("address", None) => Ok(SpendState::Address),
        ("external", None) => Ok(SpendState::External),
        ("resolved", Some(note)) => Ok(SpendState::Resolved { note }),
        ("unresolved", None) => Ok(SpendState::UnresolvedReal),
        _ => Err(DbErr::Custom(format!("unknown spend state {name}"))),
    }
}

fn state_link(state: SpendState) -> Option<[u8; 32]> {
    match state {
        SpendState::Resolved { note } => Some(note),
        SpendState::UnresolvedReal
        | SpendState::Observed
        | SpendState::Padding
        | SpendState::Address
        | SpendState::External => None,
    }
}

pub(crate) fn slot_value(slot: u64) -> Result<Value, DbErr> {
    i64::try_from(slot)
        .map(Value::from)
        .map_err(|_| DbErr::Custom("spend slot exceeds the column range".into()))
}

fn frame_values(ring: &Address, frame: &CreatedIn) -> Result<Vec<Value>, DbErr> {
    Ok(vec![
        ring.as_ref().to_vec().into(),
        slot_value(frame.slot)?,
        frame.tx_signature.as_ref().to_vec().into(),
        i32::from(frame.event_index).into(),
    ])
}

pub(crate) fn read_bytes<const N: usize>(
    row: &QueryResult,
    column: &str,
) -> Result<[u8; N], DbErr> {
    <[u8; N]>::try_from(row.try_get::<Vec<u8>>("", column)?)
        .map_err(|_| DbErr::Custom(format!("spend column {column} has another length")))
}

pub(crate) fn read_frame(row: &QueryResult) -> Result<CreatedIn, DbErr> {
    Ok(CreatedIn {
        slot: u64::try_from(row.try_get::<i64>("", "slot")?)
            .map_err(|_| DbErr::Custom("negative spend slot".into()))?,
        tx_signature: Signature::from(read_bytes::<64>(row, "tx_signature")?),
        event_index: u16::try_from(row.try_get::<i32>("", "event_index")?)
            .map_err(|_| DbErr::Custom("spend event index out of range".into()))?,
    })
}

fn position_values(position: &HistoryPosition) -> Result<[Value; 2], DbErr> {
    Ok([
        Value::BigInt(
            position
                .checkpoint()
                .map(i64::try_from)
                .transpose()
                .map_err(|_| DbErr::Custom("position exceeds the column range".into()))?,
        ),
        Value::String(position.token().map(|token| Box::new(token.to_string()))),
    ])
}

/// A token resumes inside a slot, `after_slot` alone resumes past a terminal page.
fn read_position(row: &QueryResult) -> Result<HistoryPosition, DbErr> {
    Ok(match row.try_get::<Option<String>>("", "token")? {
        Some(token) => HistoryPosition::resume(
            token
                .parse::<PaginationToken>()
                .map_err(|_| DbErr::Custom("checkpoint token does not parse".into()))?,
        ),
        None => row
            .try_get::<Option<i64>>("", "after_slot")?
            .map(u64::try_from)
            .transpose()
            .map_err(|_| DbErr::Custom("negative checkpoint slot".into()))?
            .map_or_else(HistoryPosition::default, HistoryPosition::after_slot),
    })
}

/// The one layout of a sealed enrollment, the seal last.
fn enrollment_body(held: &HeldEnrollment) -> Vec<u8> {
    [
        held.owner_key.as_slice(),
        &held.owner_hash,
        &held.member,
        &held.nullifier_pk,
        &held.list_tag,
        &held.eph_u,
        &held.list_key,
        &held.ciphertext,
    ]
    .concat()
}

fn enrollment_from_body(body: &[u8]) -> Result<HeldEnrollment, DbErr> {
    let malformed = || DbErr::Custom("enrollment body has another layout".into());
    let (owner_key, rest) = body.split_first_chunk::<32>().ok_or_else(malformed)?;
    let (owner_hash, rest) = rest.split_first_chunk::<32>().ok_or_else(malformed)?;
    let (member, rest) = rest.split_first_chunk::<32>().ok_or_else(malformed)?;
    let (nullifier_pk, rest) = rest.split_first_chunk::<32>().ok_or_else(malformed)?;
    let (list_tag, rest) = rest.split_first_chunk::<32>().ok_or_else(malformed)?;
    let (eph_u, rest) = rest.split_first_chunk::<32>().ok_or_else(malformed)?;
    let (list_key, rest) = rest.split_first_chunk::<32>().ok_or_else(malformed)?;
    let ciphertext: [u8; REGISTER_KEY_CIPHERTEXT_LEN] = rest.try_into().map_err(|_| malformed())?;
    Ok(HeldEnrollment {
        owner_key: *owner_key,
        owner_hash: *owner_hash,
        member: *member,
        nullifier_pk: *nullifier_pk,
        list_tag: *list_tag,
        eph_u: *eph_u,
        ciphertext,
        list_key: *list_key,
    })
}

/// The lease holder's writes, each transaction fenced by the lease before its first row.
pub(crate) struct ProjectionWriter<'a> {
    pub db: &'a DatabaseConnection,
    pub ring: Address,
    pub seal: &'a NoteSeal,
    pub lease: ProjectionLease,
    pub clock: Clock,
}

impl ProjectionWriter<'_> {
    /// The revision row lock orders the writer's transactions, so a follower that read revision
    /// `r` holds every row written at or below it.
    async fn begin(&self) -> Result<(DatabaseTransaction, i64), DbErr> {
        let now = self
            .clock
            .now()
            .map_err(|_| DbErr::Custom("the clock is unreadable".into()))?;
        let transaction = self.db.begin().await?;
        self.lease.fence(&transaction, now).await?;
        let backend = transaction.get_database_backend();
        transaction
            .execute(Statement::from_sql_and_values(
                backend,
                "INSERT INTO projection_revisions(ring,revision) VALUES($1,1) ON CONFLICT(ring) \
                 DO UPDATE SET revision=projection_revisions.revision+1",
                vec![self.ring_value()],
            ))
            .await?;
        let revision = read_revision(&transaction, &self.ring).await?;
        Ok((transaction, revision))
    }

    fn ring_value(&self) -> Value {
        Value::from(self.ring.as_ref().to_vec())
    }

    pub(crate) async fn commit_page(&self, delta: &PageDelta) -> Result<CommittedPage, DbErr> {
        let Self { ring, seal, .. } = self;
        let (transaction, revision) = self.begin().await?;
        let backend = transaction.get_database_backend();
        let run =
            |sql: &str, values: Vec<Value>| Statement::from_sql_and_values(backend, sql, values);
        for (commitment, note) in delta.notes() {
            let sealed = seal.seal(commitment, &note_body(note))?;
            let nullifier_tag = note
                .nullifier
                .map(|nullifier| seal.tags.nullifier_tag(&nullifier))
                .transpose()?;
            transaction
                .execute(run(
                    "INSERT INTO finalized_notes(ring,commitment,sealed,nullifier_tag,revision) \
                     VALUES($1,$2,$3,$4,$5) ON CONFLICT(ring,commitment) DO UPDATE SET \
                     sealed=excluded.sealed,nullifier_tag=excluded.nullifier_tag, \
                     revision=excluded.revision",
                    vec![
                        self.ring_value(),
                        commitment.to_vec().into(),
                        sealed.into(),
                        Value::Bytes(nullifier_tag.map(|tag| Box::new(tag.to_vec()))),
                        revision.into(),
                    ],
                ))
                .await?;
        }
        for row in delta.rows() {
            let link = state_link(row.state)
                .map(|note| seal.seal(&row.nullifier, &note))
                .transpose()?;
            let mut values = vec![self.ring_value(), row.nullifier.to_vec().into()];
            values.extend([
                slot_value(row.frame.slot)?,
                row.frame.tx_signature.as_ref().to_vec().into(),
                i32::from(row.frame.event_index).into(),
                i32::from(row.position).into(),
                state_name(row.state).into(),
                Value::Bytes(link.map(Box::new)),
                revision.into(),
            ]);
            transaction
                .execute(run(
                    "INSERT INTO finalized_spent_nullifiers(ring,nullifier,slot,tx_signature, \
                     event_index,position,state,sealed_note,revision) \
                     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(ring,nullifier) DO UPDATE SET \
                     state=excluded.state,sealed_note=excluded.sealed_note, \
                     revision=excluded.revision",
                    values,
                ))
                .await?;
        }
        for fault in delta.faults() {
            let mut values = frame_values(ring, &fault.frame)?;
            values.push(fault.nullifier.to_vec().into());
            transaction
                .execute(run(
                    "INSERT INTO spend_integrity_faults(ring,slot,tx_signature,event_index, \
                     nullifier) VALUES($1,$2,$3,$4,$5) \
                     ON CONFLICT(ring,nullifier,tx_signature,event_index) DO NOTHING",
                    values,
                ))
                .await?;
        }
        for frame in delta.read_frames() {
            transaction
                .execute(run(
                    "DELETE FROM spend_unread_frames WHERE ring=$1 AND tx_signature=$2 \
                     AND event_index=$3",
                    vec![
                        self.ring_value(),
                        frame.tx_signature.as_ref().to_vec().into(),
                        i32::from(frame.event_index).into(),
                    ],
                ))
                .await?;
        }
        // A frame unread again keeps its attempt count, the repair schedule owns it.
        for frame in delta.unread_frames() {
            transaction
                .execute(run(
                    "INSERT INTO spend_unread_frames(ring,slot,tx_signature,event_index) \
                     VALUES($1,$2,$3,$4) ON CONFLICT(ring,tx_signature,event_index) DO NOTHING",
                    frame_values(ring, frame)?,
                ))
                .await?;
        }
        OwnerNoteWrites {
            ring: *ring,
            seal,
            delta,
        }
        .write(&transaction)
        .await?;
        if let Some(checkpoint) = delta.checkpoint() {
            let [after_slot, token] = position_values(&checkpoint.position)?;
            transaction
                .execute(run(
                    "INSERT INTO spend_checkpoints(ring,after_slot,token,through_slot,block_time) \
                     VALUES($1,$2,$3,$4,$5) ON CONFLICT(ring) DO UPDATE SET \
                     after_slot=excluded.after_slot,token=excluded.token, \
                     through_slot=excluded.through_slot,block_time=excluded.block_time",
                    vec![
                        self.ring_value(),
                        after_slot,
                        token,
                        slot_value(checkpoint.through.slot)?,
                        checkpoint.through.block_time.into(),
                    ],
                ))
                .await?;
        }
        let first_unread = first_unread(&transaction, *ring).await?;
        transaction.commit().await?;
        Ok(CommittedPage {
            revision,
            first_unread,
        })
    }

    /// A page's enrollments and the tracking cursor past it commit together.
    pub(crate) async fn commit_enrollments(
        &self,
        held: &[HeldEnrollment],
        cursor: TrackingCursor,
    ) -> Result<(), DbErr> {
        let (transaction, revision) = self.begin().await?;
        let backend = transaction.get_database_backend();
        for enrollment in held {
            let member = enrollment.member();
            let sealed = self.seal.seal(&member, &enrollment_body(enrollment))?;
            let inserted = transaction
                .execute(Statement::from_sql_and_values(
                    backend,
                    "INSERT INTO held_enrollments(ring,member,sealed,owner_hash_tag,list_key_tag, \
                     revision) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(ring,member) DO NOTHING",
                    vec![
                        self.ring_value(),
                        member.to_vec().into(),
                        sealed.into(),
                        self.seal
                            .tags
                            .owner_hash_tag(&enrollment.owner_hash)?
                            .to_vec()
                            .into(),
                        self.seal
                            .tags
                            .list_key_tag(&enrollment.list_key)?
                            .to_vec()
                            .into(),
                        revision.into(),
                    ],
                ))
                .await?
                .rows_affected();
            if inserted != 0 {
                transaction.execute(Statement::from_sql_and_values(
                    backend,
                    "INSERT INTO pending_derivations(ring,member) VALUES($1,$2) ON CONFLICT(ring,member) DO NOTHING",
                    vec![self.ring_value(), member.to_vec().into()],
                )).await?;
            }
        }
        let cursor = i64::try_from(cursor.next_leaf())
            .map_err(|_| DbErr::Custom("tracking cursor past i64".into()))?;
        transaction
            .execute(Statement::from_sql_and_values(
                backend,
                "INSERT INTO tracking_cursors(ring,next_leaf) VALUES($1,$2) \
                 ON CONFLICT(ring) DO UPDATE SET next_leaf=excluded.next_leaf",
                vec![self.ring_value(), cursor.into()],
            ))
            .await?;
        transaction.commit().await
    }

    pub(crate) async fn pending_owners(&self) -> Result<Vec<LateOwner>, DbErr> {
        let limit = i64::try_from(MAX_LATE_OWNERS)
            .map_err(|_| DbErr::Custom("pending owner limit exceeds the column range".into()))?;
        self.db
            .query_all(Statement::from_sql_and_values(
                self.db.get_database_backend(),
                "SELECT e.member,e.sealed,p.after_tag FROM held_enrollments e JOIN \
                 pending_derivations p ON e.ring=p.ring AND e.member=p.member WHERE e.ring=$1 \
                 ORDER BY e.member LIMIT $2",
                vec![self.ring_value(), limit.into()],
            ))
            .await?
            .iter()
            .map(|row| {
                let resume = row
                    .try_get::<Option<Vec<u8>>>("", "after_tag")?
                    .map(<[u8; 32]>::try_from)
                    .transpose()
                    .map_err(|_| DbErr::Custom("resume tag has another length".into()))?;
                Ok(LateOwner {
                    owner: read_enrollment(row, self.seal)?.owner_key,
                    resume,
                })
            })
            .collect()
    }

    pub(crate) async fn record_attempts(
        &self,
        attempts: &[(CreatedIn, RepairAttempt)],
    ) -> Result<(), DbErr> {
        let (transaction, _) = self.begin().await?;
        for (frame, attempt) in attempts {
            transaction
                .execute(Statement::from_sql_and_values(
                    transaction.get_database_backend(),
                    "UPDATE spend_unread_frames SET attempts=$1,retry_after=$2 WHERE ring=$3 \
                     AND tx_signature=$4 AND event_index=$5",
                    vec![
                        i64::from(attempt.attempts).into(),
                        slot_value(attempt.retry_after)?,
                        self.ring_value(),
                        frame.tx_signature.as_ref().to_vec().into(),
                        i32::from(frame.event_index).into(),
                    ],
                ))
                .await?;
        }
        transaction.commit().await
    }
}

/// Reads every row of one ring from one snapshot, a commit between two reads shows in neither.
#[must_use]
pub(crate) struct LoadSpends<'a> {
    pub db: &'a DatabaseConnection,
    pub ring: Address,
    pub seal: &'a NoteSeal,
    pub scope: HistoryScope,
}

impl LoadSpends<'_> {
    pub(crate) async fn load(self) -> Result<LoadedProjection, DbErr> {
        let snapshot = read_snapshot(self.db).await?;
        let loaded = self.read(&snapshot).await?;
        snapshot.commit().await?;
        Ok(loaded)
    }

    async fn read(&self, snapshot: &DatabaseTransaction) -> Result<LoadedProjection, DbErr> {
        let Self {
            ring, seal, scope, ..
        } = self;
        let query = |sql: &str| {
            Statement::from_sql_and_values(
                snapshot.get_database_backend(),
                sql,
                vec![Value::from(ring.as_ref().to_vec())],
            )
        };
        let mut loaded = LoadedProjection {
            revision: read_revision(snapshot, ring).await?,
            ..LoadedProjection::default()
        };
        let spends = &mut loaded.spends;
        if *scope == HistoryScope::Everything {
            for row in snapshot
                .query_all(query(&format!(
                    "SELECT {NOTE_COLUMNS} FROM finalized_notes WHERE ring=$1"
                )))
                .await?
            {
                spends.notes.push(read_note(&row, seal)?);
            }
            for row in snapshot
                .query_all(query(&format!(
                    "SELECT {ROW_COLUMNS} FROM finalized_spent_nullifiers \
                     WHERE ring=$1"
                )))
                .await?
            {
                spends.rows.push(read_spend_row(&row, seal)?);
            }
        }
        if *scope == HistoryScope::Everything {
            for row in snapshot
                .query_all(query(
                    "SELECT slot,tx_signature,event_index,attempts,retry_after FROM \
                     spend_unread_frames WHERE ring=$1",
                ))
                .await?
            {
                let frame = read_frame(&row)?;
                let attempt = RepairAttempt {
                    attempts: u32::try_from(row.try_get::<i64>("", "attempts")?)
                        .map_err(|_| DbErr::Custom("repair attempts out of range".into()))?,
                    retry_after: u64::try_from(row.try_get::<i64>("", "retry_after")?)
                        .map_err(|_| DbErr::Custom("negative repair time".into()))?,
                };
                spends.unread.push(frame);
                if attempt.attempts > 0 {
                    loaded.repairs.push((frame, attempt));
                }
            }
            for row in snapshot
                .query_all(query(
                    "SELECT nullifier,slot,tx_signature,event_index FROM spend_integrity_faults \
                     WHERE ring=$1",
                ))
                .await?
            {
                spends.faults.push(SpendRow {
                    nullifier: read_bytes(&row, "nullifier")?,
                    frame: read_frame(&row)?,
                    position: 0,
                    state: SpendState::Observed,
                });
            }
        } else {
            spends.unread.extend(first_unread(snapshot, *ring).await?);
        }
        if let Some(row) = snapshot
            .query_one(query(
                "SELECT after_slot,token,through_slot,block_time FROM spend_checkpoints \
                 WHERE ring=$1",
            ))
            .await?
        {
            spends.checkpoint = Checkpoint {
                position: read_position(&row)?,
                through: Context {
                    slot: u64::try_from(row.try_get::<i64>("", "through_slot")?)
                        .map_err(|_| DbErr::Custom("negative checkpoint slot".into()))?,
                    block_time: row.try_get("", "block_time")?,
                },
            };
        }
        if *scope == HistoryScope::Everything {
            for row in snapshot
                .query_all(query(&format!(
                    "SELECT {ENROLLMENT_COLUMNS} FROM held_enrollments WHERE ring=$1"
                )))
                .await?
            {
                loaded.enrollments.push(read_enrollment(&row, seal)?);
            }
        }
        if let Some(row) = snapshot
            .query_one(query(
                "SELECT next_leaf FROM tracking_cursors WHERE ring=$1",
            ))
            .await?
        {
            loaded.tracking_cursor = u64::try_from(row.try_get::<i64>("", "next_leaf")?)
                .ok()
                .and_then(TrackingCursor::stored)
                .ok_or_else(|| DbErr::Custom("tracking cursor names the sentinel".into()))?;
        }
        Ok(loaded)
    }
}

pub(crate) const NOTE_COLUMNS: &str = "commitment,sealed";
pub(crate) const ENROLLMENT_COLUMNS: &str = "member,sealed";

/// One enrollment row selected with `ENROLLMENT_COLUMNS`, its body bound to its member.
pub(crate) fn read_enrollment(row: &QueryResult, seal: &NoteSeal) -> Result<HeldEnrollment, DbErr> {
    let member: [u8; 32] = read_bytes(row, "member")?;
    let body = seal.open(&member, &row.try_get::<Vec<u8>>("", "sealed")?)?;
    let held = enrollment_from_body(&body)?;
    if held.member() != member {
        return Err(DbErr::Custom("enrollment row names another member".into()));
    }
    Ok(held)
}
pub(crate) const ROW_COLUMNS: &str =
    "nullifier,slot,tx_signature,event_index,position,state,sealed_note";

/// One note row selected with `NOTE_COLUMNS`.
pub(crate) fn read_note(
    row: &QueryResult,
    seal: &NoteSeal,
) -> Result<([u8; 32], StoredUtxo), DbErr> {
    let commitment: [u8; 32] = read_bytes(row, "commitment")?;
    let body = seal.open(&commitment, &row.try_get::<Vec<u8>>("", "sealed")?)?;
    Ok((commitment, note_from_body(&body)?))
}

/// One spend row selected with `ROW_COLUMNS`, its resolved note link opened under the seal.
pub(crate) fn read_spend_row(row: &QueryResult, seal: &NoteSeal) -> Result<SpendRow, DbErr> {
    let nullifier: [u8; 32] = read_bytes(row, "nullifier")?;
    let link = row
        .try_get::<Option<Vec<u8>>>("", "sealed_note")?
        .map(|sealed| {
            let opened = seal.open(&nullifier, &sealed)?;
            <[u8; 32]>::try_from(opened)
                .map_err(|_| DbErr::Custom("spend link has another length".into()))
        })
        .transpose()?;
    Ok(SpendRow {
        nullifier,
        frame: read_frame(row)?,
        position: u16::try_from(row.try_get::<i32>("", "position")?)
            .map_err(|_| DbErr::Custom("spend position out of range".into()))?,
        state: state_of(&row.try_get::<String>("", "state")?, link)?,
    })
}

/// Zero before the ring's first commit.
pub(crate) async fn read_revision(db: &impl ConnectionTrait, ring: &Address) -> Result<i64, DbErr> {
    let row = db
        .query_one(Statement::from_sql_and_values(
            db.get_database_backend(),
            "SELECT revision FROM projection_revisions WHERE ring=$1",
            vec![ring.as_ref().to_vec().into()],
        ))
        .await?;
    row.map_or(Ok(0), |row| row.try_get("", "revision"))
}

/// Postgres pins one snapshot for the transaction, a SQLite read transaction pins it at its
/// first read.
pub(crate) async fn read_snapshot(db: &DatabaseConnection) -> Result<DatabaseTransaction, DbErr> {
    match db.get_database_backend() {
        DatabaseBackend::Postgres => {
            db.begin_with_config(
                Some(IsolationLevel::RepeatableRead),
                Some(AccessMode::ReadOnly),
            )
            .await
        }
        DatabaseBackend::Sqlite | DatabaseBackend::MySql => db.begin().await,
    }
}

#[cfg(test)]
#[path = "projection_tests.rs"]
mod projection_tests;
