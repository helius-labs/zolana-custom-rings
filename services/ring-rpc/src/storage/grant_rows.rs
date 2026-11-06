use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::hmac::{Hmac, Mac};
use sea_orm::{ConnectionTrait, Statement, Value};
use sha2::Sha256;
use solana_address::Address;
use spr_keypair::KeypairError;
use zeroize::Zeroizing;
use zolana_ring_client::{rpc::ReaderGrantAction, ReaderKey};

use crate::{
    database::Store,
    error::RingRpcError,
    grants::{GrantQuery, GrantSource},
    keys::GRANT_ROW_KEY_INFO,
};

const NONCE_LEN: usize = 12;
const ACTION_AND_TIMESTAMP_LEN: usize = 1 + 8;

pub(crate) struct GrantRows {
    store: Store,
    key: GrantRowKey,
}

pub(crate) struct GrantRowKey {
    cipher: Aes256Gcm,
    lookup: Zeroizing<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GrantPair {
    pub ring: Address,
    /// `None` for a ring-wide grant.
    pub wallet: Option<Address>,
    pub reader: ReaderKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GrantRow {
    pub pair: GrantPair,
    pub action: ReaderGrantAction,
    /// The signed Unix seconds, the newest row of a pair holds.
    pub timestamp: u64,
}

impl GrantRowKey {
    pub(crate) fn derive(secret: &[u8]) -> Result<Self, RingRpcError> {
        let mut okm = Zeroizing::new([0u8; 64]);
        hkdf::Hkdf::<Sha256>::new(None, secret)
            .expand(GRANT_ROW_KEY_INFO, okm.as_mut_slice())
            .map_err(|_| KeypairError::Hkdf)?;
        // Disjoint halves, the cipher key never keys the lookup.
        let (cipher, lookup) = okm.split_at(32);
        Ok(Self {
            cipher: Aes256Gcm::new_from_slice(cipher).map_err(|_| KeypairError::Hkdf)?,
            lookup: Zeroizing::new(lookup.try_into().map_err(|_| KeypairError::Hkdf)?),
        })
    }

    /// The only plaintext a row stores beside its insert id.
    fn lookup(&self, reader: &ReaderKey) -> Result<[u8; 32], RingRpcError> {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(self.lookup.as_slice())
            .map_err(|_| KeypairError::Hkdf)?;
        mac.update(&reader.to_bytes());
        Ok(mac.finalize().into_bytes().into())
    }

    /// The lookup is the associated data, a row moved to another reader fails to open.
    fn seal(&self, lookup: &[u8; 32], body: &[u8]) -> Result<Vec<u8>, RingRpcError> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let sealed = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: body,
                    aad: lookup,
                },
            )
            .map_err(|_| RingRpcError::InvalidGrantRow)?;
        Ok([nonce.as_slice(), &sealed].concat())
    }

    fn open(&self, lookup: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, RingRpcError> {
        let (nonce, ciphertext) = sealed
            .split_at_checked(NONCE_LEN)
            .ok_or(RingRpcError::InvalidGrantRow)?;
        self.cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: lookup,
                },
            )
            .map_err(|_| RingRpcError::InvalidGrantRow)
    }
}

impl GrantRow {
    /// A ring-wide row leaves the wallet out.
    fn body(&self) -> Vec<u8> {
        let action = match self.action {
            ReaderGrantAction::Grant => 1,
            ReaderGrantAction::Revoke => 0,
        };
        [
            self.pair.ring.as_ref(),
            self.pair.wallet.as_ref().map_or(&[][..], AsRef::as_ref),
            &[action],
            &self.timestamp.to_le_bytes(),
        ]
        .concat()
    }

    fn from_body(reader: ReaderKey, body: &[u8]) -> Result<Self, RingRpcError> {
        let invalid = || RingRpcError::InvalidGrantRow;
        let (ring, rest) = body.split_first_chunk::<32>().ok_or_else(invalid)?;
        let (wallet, tail) = rest
            .split_last_chunk::<ACTION_AND_TIMESTAMP_LEN>()
            .ok_or_else(invalid)?;
        let wallet = match wallet {
            [] => None,
            wallet => Some(Address::new_from_array(
                wallet.try_into().map_err(|_| invalid())?,
            )),
        };
        let (action, timestamp) = tail.split_first().ok_or_else(invalid)?;
        Ok(Self {
            pair: GrantPair {
                ring: Address::new_from_array(*ring),
                wallet,
                reader,
            },
            action: match action {
                1 => ReaderGrantAction::Grant,
                0 => ReaderGrantAction::Revoke,
                _ => return Err(invalid()),
            },
            timestamp: u64::from_le_bytes(timestamp.try_into().map_err(|_| invalid())?),
        })
    }
}

impl GrantRows {
    pub(crate) fn new(store: Store, key: GrantRowKey) -> Self {
        Self { store, key }
    }

    /// Appends the row, a stale signature leaves the newer action in force.
    pub(crate) async fn write(&self, row: GrantRow) -> Result<ReaderGrantAction, RingRpcError> {
        let lookup = self.key.lookup(&row.pair.reader)?;
        let sealed = self.key.seal(&lookup, &row.body())?;
        let db = self.store.connection();
        db.execute(Statement::from_sql_and_values(
            db.get_database_backend(),
            "INSERT INTO grants (reader, sealed) VALUES ($1, $2)",
            [bytes(&lookup), Value::from(sealed)],
        ))
        .await?;
        let rows = self.rows(row.pair.reader).await?;
        Ok(newest(&rows, row.pair).map_or(row.action, |newest| newest.action))
    }

    /// In insert order.
    async fn rows(&self, reader: ReaderKey) -> Result<Vec<GrantRow>, RingRpcError> {
        let lookup = self.key.lookup(&reader)?;
        let db = self.store.connection();
        let rows = db
            .query_all(Statement::from_sql_and_values(
                db.get_database_backend(),
                "SELECT sealed FROM grants WHERE reader = $1 ORDER BY id",
                [bytes(&lookup)],
            ))
            .await?;
        rows.iter()
            .map(|row| {
                let sealed: Vec<u8> = row.try_get("", "sealed")?;
                GrantRow::from_body(reader, &self.key.open(&lookup, &sealed)?)
            })
            .collect()
    }
}

impl GrantSource for GrantRows {
    async fn grants(&self, query: GrantQuery) -> Result<bool, RingRpcError> {
        let rows = self.rows(query.reader).await?;
        let granted = |wallet| {
            let pair = GrantPair {
                ring: query.ring,
                wallet,
                reader: query.reader,
            };
            newest(&rows, pair).is_some_and(|row| row.action == ReaderGrantAction::Grant)
        };
        Ok(granted(None) || query.wallet.is_some_and(|wallet| granted(Some(wallet))))
    }
}

/// The pair's row with the latest timestamp, the later insert on a tie.
fn newest(rows: &[GrantRow], pair: GrantPair) -> Option<GrantRow> {
    rows.iter()
        .filter(|row| row.pair == pair)
        .max_by_key(|row| row.timestamp)
        .copied()
}

fn bytes(value: &[u8; 32]) -> Value {
    value.to_vec().into()
}
