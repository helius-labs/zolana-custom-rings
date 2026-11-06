use std::{collections::HashMap, mem::offset_of, time::Duration};

use solana_account::Account;
use solana_address::Address;
use solana_rpc_client_api::custom_error::JSON_RPC_SERVER_ERROR_MIN_CONTEXT_SLOT_NOT_REACHED;
use spr_client::{AsyncRpc, ClientError, ProgramAccountsFilter};
use spr_interface::{
    pda,
    state::{
        discriminator::{SPL_ASSET_COUNTER, SPL_ASSET_REGISTRY},
        SplAssetCounter, SplAssetRegistry,
    },
    PROGRAM_ID_PUBKEY,
};
use spr_transaction::{Mint, SOL_ASSET_ID, SOL_MINT};
use thiserror::Error;

pub const COMPACT_ASSET_LOOKUP_BUDGET: usize = 32;
const READ_ATTEMPTS: u32 = 3;
const READ_BACKOFF: Duration = Duration::from_millis(100);
/// Lowercase causes in the Solana client's message that clear without a change in the request.
const TRANSIENT_READ_CAUSES: [&str; 11] = [
    "error sending request",
    "request or response body error",
    "operation timed out",
    "http status client error (429",
    "http status server error (502",
    "http status server error (503",
    "http status server error (504",
    "connection refused",
    "connection reset",
    "connection aborted",
    "broken pipe",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum CompactAssetResolution {
    Foreign,
    Resolved(Mint),
    Paused,
}

#[derive(Debug, Error)]
pub enum CompactAssetError {
    #[error(transparent)]
    Source(Box<ClientError>),
    #[error("the asset allocation counter is invalid")]
    InvalidCounter,
    #[error("the asset registry does not bind allocated asset {asset_id}")]
    InvalidRegistry { asset_id: u64 },
}

#[must_use]
pub struct CompactAssetRead<'a, R: ?Sized> {
    pub client: &'a R,
    pub target_slot: u64,
}

pub struct CompactAssetResolver<'a, R: ?Sized> {
    client: &'a R,
    target_slot: u64,
    next_id: u64,
    remaining: usize,
    cache: HashMap<u64, Mint>,
}

impl<'a, R: AsyncRpc + ?Sized> CompactAssetRead<'a, R> {
    pub async fn open(self) -> Result<CompactAssetResolver<'a, R>, CompactAssetError> {
        let filter = ProgramAccountsFilter::new(SplAssetCounter::SIZE)
            .with_memcmp(0, [SPL_ASSET_COUNTER])
            .with_min_context_slot(self.target_slot);
        let accounts = read_accounts(self.client, &filter).await?;
        let [(address, account)] = accounts.as_slice() else {
            return Err(CompactAssetError::InvalidCounter);
        };
        if *address != pda::spl_asset_counter()
            || account.owner != PROGRAM_ID_PUBKEY
            || !filter.matches(&account.data)
        {
            return Err(CompactAssetError::InvalidCounter);
        }
        let counter = asset_counter(&account.data).ok_or(CompactAssetError::InvalidCounter)?;
        Ok(CompactAssetResolver {
            client: self.client,
            target_slot: self.target_slot,
            next_id: counter.next_id,
            remaining: COMPACT_ASSET_LOOKUP_BUDGET,
            cache: HashMap::new(),
        })
    }
}

impl<R: AsyncRpc + ?Sized> CompactAssetResolver<'_, R> {
    pub async fn resolve(
        &mut self,
        asset_id: u64,
    ) -> Result<CompactAssetResolution, CompactAssetError> {
        if asset_id == SOL_ASSET_ID {
            return Ok(CompactAssetResolution::Resolved(Mint::SOL));
        }
        if asset_id < SplAssetCounter::FIRST_ASSET_ID || asset_id >= self.next_id {
            return Ok(CompactAssetResolution::Foreign);
        }
        if let Some(mint) = self.cache.get(&asset_id) {
            return Ok(CompactAssetResolution::Resolved(*mint));
        }
        if self.remaining == 0 {
            return Ok(CompactAssetResolution::Paused);
        }
        self.remaining -= 1;
        let filter = ProgramAccountsFilter::new(SplAssetRegistry::SIZE)
            .with_memcmp(0, [SPL_ASSET_REGISTRY])
            .with_memcmp(
                offset_of!(SplAssetRegistry, asset_id),
                asset_id.to_le_bytes(),
            )
            .with_min_context_slot(self.target_slot);
        let accounts = read_accounts(self.client, &filter).await?;
        let [(address, account)] = accounts.as_slice() else {
            return Err(CompactAssetError::InvalidRegistry { asset_id });
        };
        if account.owner != PROGRAM_ID_PUBKEY || !filter.matches(&account.data) {
            return Err(CompactAssetError::InvalidRegistry { asset_id });
        }
        let registration = SplAssetRegistry::from_account_bytes(&account.data)
            .map_err(|_| CompactAssetError::InvalidRegistry { asset_id })?;
        if *address != pda::spl_asset_registry(&registration.mint)
            || registration.mint == SOL_MINT
            || registration.asset_id != asset_id
            || self
                .cache
                .values()
                .any(|known| known.asset == registration.mint)
        {
            return Err(CompactAssetError::InvalidRegistry { asset_id });
        }
        let mint = Mint::new(registration.mint, asset_id);
        self.cache.insert(asset_id, mint);
        Ok(CompactAssetResolution::Resolved(mint))
    }

    pub fn target_slot(&self) -> u64 {
        self.target_slot
    }

    pub fn remaining_lookups(&self) -> usize {
        self.remaining
    }
}

async fn read_accounts<R: AsyncRpc + ?Sized>(
    client: &R,
    filter: &ProgramAccountsFilter,
) -> Result<Vec<(Address, Account)>, CompactAssetError> {
    let mut attempt = 1;
    loop {
        match client
            .get_program_accounts_filtered(PROGRAM_ID_PUBKEY, filter)
            .await
        {
            Err(error) if attempt < READ_ATTEMPTS && transient_read(client, &error) => {
                tokio::time::sleep(READ_BACKOFF * attempt).await;
                attempt += 1;
            }
            read => return read.map_err(|error| CompactAssetError::Source(Box::new(error))),
        }
    }
}

/// The pinned Solana client keeps a read failure only as its message.
pub fn transient_read(client: &(impl AsyncRpc + ?Sized), error: &ClientError) -> bool {
    if client.should_retry(error) {
        return true;
    }
    let ClientError::Rpc(message) = error else {
        return false;
    };
    let message = message.to_lowercase();
    TRANSIENT_READ_CAUSES
        .iter()
        .any(|cause| message.contains(cause))
        || message.contains(&format!(
            "rpc response error {JSON_RPC_SERVER_ERROR_MIN_CONTEXT_SLOT_NOT_REACHED}:"
        ))
}

/// The exact counter layout under its discriminator, a `next_id` below the first SPL id is corrupt.
fn asset_counter(data: &[u8]) -> Option<SplAssetCounter> {
    let counter: SplAssetCounter = bytemuck::try_pod_read_unaligned(data).ok()?;
    counter.check_discriminator().ok()?;
    (counter.next_id >= SplAssetCounter::FIRST_ASSET_ID).then_some(counter)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    };

    use std::io;

    use async_trait::async_trait;
    use solana_rpc_client_api::{
        client_error::{reqwest, Error as RpcClientError, ErrorKind},
        request::{RpcError, RpcResponseErrorData},
    };

    use super::*;

    struct RegistryRpc {
        counter: (Address, Account),
        registrations: Vec<(Address, Account)>,
        filters: Mutex<Vec<ProgramAccountsFilter>>,
        unavailable: AtomicBool,
        /// Answered ahead of any account, last first.
        failures: Mutex<Vec<ClientError>>,
    }

    impl RegistryRpc {
        fn new(next_id: u64) -> Self {
            let mut data = vec![SPL_ASSET_COUNTER, 0, 0, 0, 0, 0, 0, 0];
            data.extend_from_slice(&next_id.to_le_bytes());
            Self {
                counter: (
                    pda::spl_asset_counter(),
                    Account {
                        owner: PROGRAM_ID_PUBKEY,
                        data,
                        ..Account::default()
                    },
                ),
                registrations: (SplAssetCounter::FIRST_ASSET_ID..next_id)
                    .map(|asset_id| {
                        let mut bytes = [7; 32];
                        bytes[..8].copy_from_slice(&asset_id.to_le_bytes());
                        let mint = Address::new_from_array(bytes);
                        (
                            pda::spl_asset_registry(&mint),
                            Account {
                                owner: PROGRAM_ID_PUBKEY,
                                data: SplAssetRegistry::account_bytes(mint, asset_id).to_vec(),
                                ..Account::default()
                            },
                        )
                    })
                    .collect(),
                filters: Mutex::new(Vec::new()),
                unavailable: AtomicBool::new(false),
                failures: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl AsyncRpc for RegistryRpc {
        async fn get_program_accounts_filtered(
            &self,
            program_id: Address,
            filter: &ProgramAccountsFilter,
        ) -> Result<Vec<(Address, Account)>, ClientError> {
            assert_eq!(program_id, PROGRAM_ID_PUBKEY);
            assert_eq!(filter.min_context_slot(), Some(99));
            self.filters.lock().unwrap().push(filter.clone());
            if let Some(failure) = self.failures.lock().unwrap().pop() {
                return Err(failure);
            }
            if filter.data_size() == SplAssetCounter::SIZE {
                return Ok(vec![self.counter.clone()]);
            }
            if self.unavailable.load(Ordering::Relaxed) {
                return Err(ClientError::Rpc("registry unavailable".to_owned()));
            }
            Ok(self
                .registrations
                .iter()
                .filter(|(_, account)| filter.matches(&account.data))
                .cloned()
                .collect())
        }
    }

    #[tokio::test]
    async fn impossible_ids_and_sol_do_not_read_registries() {
        let rpc = RegistryRpc::new(4);
        let mut resolver = CompactAssetRead {
            client: &rpc,
            target_slot: 99,
        }
        .open()
        .await
        .unwrap();
        assert_eq!(
            resolver.resolve(0).await.unwrap(),
            CompactAssetResolution::Foreign
        );
        assert_eq!(
            resolver.resolve(4).await.unwrap(),
            CompactAssetResolution::Foreign
        );
        assert_eq!(
            resolver.resolve(u64::MAX).await.unwrap(),
            CompactAssetResolution::Foreign
        );
        assert_eq!(
            resolver.resolve(1).await.unwrap(),
            CompactAssetResolution::Resolved(Mint::SOL)
        );
        assert_eq!(rpc.filters.lock().unwrap().len(), 1);
        assert_eq!(resolver.remaining_lookups(), COMPACT_ASSET_LOOKUP_BUDGET);
    }

    #[tokio::test]
    async fn cached_ids_do_not_consume_lookup_budget() {
        let rpc = RegistryRpc::new(40);
        let mut resolver = CompactAssetRead {
            client: &rpc,
            target_slot: 99,
        }
        .open()
        .await
        .unwrap();
        let first = resolver.resolve(2).await.unwrap();
        assert!(matches!(
            first,
            CompactAssetResolution::Resolved(Mint { asset_id: 2, .. })
        ));
        assert_eq!(resolver.resolve(2).await.unwrap(), first);
        assert_eq!(
            resolver.remaining_lookups(),
            COMPACT_ASSET_LOOKUP_BUDGET - 1
        );
        for asset_id in 3..34 {
            assert!(matches!(
                resolver.resolve(asset_id).await.unwrap(),
                CompactAssetResolution::Resolved(_)
            ));
        }
        assert_eq!(
            resolver.resolve(34).await.unwrap(),
            CompactAssetResolution::Paused
        );
        assert_eq!(resolver.resolve(2).await.unwrap(), first);
        assert_eq!(
            rpc.filters.lock().unwrap().len(),
            COMPACT_ASSET_LOOKUP_BUDGET + 1
        );
        assert_eq!(resolver.cache.len(), COMPACT_ASSET_LOOKUP_BUDGET);
    }

    #[tokio::test]
    async fn missing_allocated_mapping_is_not_foreign() {
        let mut rpc = RegistryRpc::new(4);
        rpc.registrations.clear();
        let mut resolver = CompactAssetRead {
            client: &rpc,
            target_slot: 99,
        }
        .open()
        .await
        .unwrap();
        assert!(matches!(
            resolver.resolve(2).await,
            Err(CompactAssetError::InvalidRegistry { asset_id: 2 })
        ));
        assert!(resolver.cache.is_empty());
    }

    #[tokio::test]
    async fn registry_owner_and_address_are_checked() {
        for wrong_owner in [false, true] {
            let mut rpc = RegistryRpc::new(3);
            if wrong_owner {
                rpc.registrations[0].1.owner = SOL_MINT;
            } else {
                rpc.registrations[0].0 = SOL_MINT;
            }
            let mut resolver = CompactAssetRead {
                client: &rpc,
                target_slot: 99,
            }
            .open()
            .await
            .unwrap();
            assert!(matches!(
                resolver.resolve(2).await,
                Err(CompactAssetError::InvalidRegistry { asset_id: 2 })
            ));
            assert!(resolver.cache.is_empty());
        }
    }

    #[tokio::test]
    async fn counter_owner_address_and_range_are_checked() {
        for invalid in 0..3 {
            let mut rpc = RegistryRpc::new(2);
            match invalid {
                0 => rpc.counter.1.owner = SOL_MINT,
                1 => rpc.counter.0 = SOL_MINT,
                _ => rpc.counter.1.data[8..].fill(0),
            }
            assert!(matches!(
                CompactAssetRead {
                    client: &rpc,
                    target_slot: 99,
                }
                .open()
                .await,
                Err(CompactAssetError::InvalidCounter)
            ));
        }
    }

    #[tokio::test]
    async fn source_failure_does_not_cache_absence() {
        let rpc = RegistryRpc::new(3);
        let mut resolver = CompactAssetRead {
            client: &rpc,
            target_slot: 99,
        }
        .open()
        .await
        .unwrap();
        rpc.unavailable.store(true, Ordering::Relaxed);
        assert!(matches!(
            resolver.resolve(2).await,
            Err(CompactAssetError::Source(_))
        ));
        assert!(resolver.cache.is_empty());
        rpc.unavailable.store(false, Ordering::Relaxed);
        assert!(matches!(
            resolver.resolve(2).await.unwrap(),
            CompactAssetResolution::Resolved(_)
        ));
        assert_eq!(
            resolver.remaining_lookups(),
            COMPACT_ASSET_LOOKUP_BUDGET - 2
        );
    }

    /// The message the pinned `AsyncSolanaRpc` keeps of a program-accounts read failure.
    fn pinned_read_error(kind: ErrorKind) -> ClientError {
        ClientError::Rpc(format!(
            "get_program_accounts {PROGRAM_ID_PUBKEY}: {}",
            RpcClientError::from(kind)
        ))
    }

    fn response_error(code: i64) -> ClientError {
        pinned_read_error(ErrorKind::RpcError(RpcError::RpcResponseError {
            code,
            message: "request refused".into(),
            data: RpcResponseErrorData::Empty,
        }))
    }

    fn reset() -> ClientError {
        pinned_read_error(ErrorKind::Io(io::Error::from(
            io::ErrorKind::ConnectionReset,
        )))
    }

    fn read(rpc: &RegistryRpc) -> CompactAssetRead<'_, RegistryRpc> {
        CompactAssetRead {
            client: rpc,
            target_slot: 99,
        }
    }

    #[tokio::test]
    async fn only_a_transient_read_retries_within_its_bound() {
        let rpc = RegistryRpc::new(3);
        *rpc.failures.lock().unwrap() = vec![
            reset(),
            response_error(JSON_RPC_SERVER_ERROR_MIN_CONTEXT_SLOT_NOT_REACHED),
        ];
        assert!(read(&rpc).open().await.is_ok());
        assert_eq!(rpc.filters.lock().unwrap().len(), 3);

        let rpc = RegistryRpc::new(3);
        *rpc.failures.lock().unwrap() = vec![reset(), reset(), reset()];
        assert!(matches!(
            read(&rpc).open().await,
            Err(CompactAssetError::Source(error)) if transient_read(&rpc, &error)
        ));
        assert_eq!(rpc.filters.lock().unwrap().len(), READ_ATTEMPTS as usize);

        for permanent in [
            response_error(-32602),
            ClientError::UnsupportedRpcMethod("read"),
        ] {
            let rpc = RegistryRpc::new(3);
            *rpc.failures.lock().unwrap() = vec![permanent];
            assert!(matches!(
                read(&rpc).open().await,
                Err(CompactAssetError::Source(error)) if !transient_read(&rpc, &error)
            ));
            assert_eq!(rpc.filters.lock().unwrap().len(), 1);
        }
    }

    #[test]
    fn transient_read_names_only_retryable_statuses() {
        let rpc = RegistryRpc::new(2);
        for (status, transient) in [
            (429, true),
            (502, true),
            (503, true),
            (504, true),
            (400, false),
            (403, false),
            (500, false),
        ] {
            let response = http::Response::builder().status(status).body("").unwrap();
            let source = reqwest::Response::from(response)
                .error_for_status()
                .unwrap_err();
            assert_eq!(
                transient_read(&rpc, &pinned_read_error(ErrorKind::Reqwest(source))),
                transient,
                "{status}"
            );
        }
    }

    #[tokio::test]
    async fn the_pinned_client_reads_a_refused_connection_as_transient() {
        let rpc = spr_client::AsyncSolanaRpc::new("http://127.0.0.1:1");
        let error = rpc
            .get_program_accounts_filtered(PROGRAM_ID_PUBKEY, &ProgramAccountsFilter::new(1))
            .await
            .unwrap_err();
        assert!(transient_read(&rpc, &error), "{error}");
    }
}
