use std::future::Future;

use solana_address::Address;
use zolana_ring_client::{
    rpc::{
        AuditedMergesPage, AuditedUtxoView, GetDecryptedTransactionsResponse,
        GetWalletActivityResponse, WalletActivity, WalletActivityPage,
    },
    ReaderKey,
};
use zolana_ring_policy::{ListId, Member};

use crate::{
    error::{GrantRefusal, RingRpcError},
    grant_rows::GrantRows,
    upstream::{RecordsTip, TransactionSource, VerifiedOpenings},
    utxos::AuditStore,
};

#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantQuery {
    pub ring: Address,
    pub reader: ReaderKey,
    pub wallet: Option<Address>,
}

/// Fixed at startup, a read consults no other grant source.
pub(crate) enum Grants {
    Tree,
    Database(Box<GrantRows>),
}

/// A named wallet narrows any grant to that wallet's rows.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadScope {
    Ring,
    Wallet(WalletScope),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WalletScope {
    wallet: Address,
}

pub(crate) trait GrantSource {
    /// A ring-wide grant covers every query, a wallet grant only a query naming that wallet.
    fn grants(&self, query: GrantQuery) -> impl Future<Output = Result<bool, RingRpcError>> + Send;
}

/// `Reader` lists of the ring's own storage tree, opened under its registry's newest root.
pub(crate) struct TreeGrants<'a, S> {
    pub source: &'a S,
}

impl WalletScope {
    const fn new(wallet: Address) -> Self {
        Self { wallet }
    }

    /// Reads the page's input rows once, then names each input's party from them.
    pub(crate) async fn activity(
        self,
        response: GetDecryptedTransactionsResponse,
        store: &AuditStore,
    ) -> Result<GetWalletActivityResponse, RingRpcError> {
        let parties = store
            .input_parties(
                &self.wallet,
                response
                    .value
                    .items
                    .iter()
                    .flat_map(|item| &item.nullifiers),
            )
            .await?;
        Ok(GetWalletActivityResponse {
            context: response.context,
            value: WalletActivityPage {
                items: response
                    .value
                    .items
                    .into_iter()
                    .filter_map(|item| {
                        WalletActivity::of(self.wallet, item, |nullifier| parties.owns(nullifier))
                    })
                    .collect(),
                cursor: response.value.cursor,
            },
        })
    }
}

impl ReadScope {
    pub(crate) const fn new(wallet: Option<Address>) -> Self {
        match wallet {
            Some(wallet) => Self::Wallet(WalletScope::new(wallet)),
            None => Self::Ring,
        }
    }

    pub(crate) fn merges(self, page: &mut AuditedMergesPage) {
        if let Self::Wallet(scope) = self {
            page.opened
                .retain(|merge| merge.owner_key.0 == scope.wallet);
        }
    }

    pub(crate) fn utxo(self, view: Option<AuditedUtxoView>) -> Option<AuditedUtxoView> {
        view.filter(|view| match self {
            Self::Ring => true,
            Self::Wallet(scope) => view.utxo.owner_key.0 == scope.wallet,
        })
    }
}

impl<S: TransactionSource> GrantSource for TreeGrants<'_, S> {
    async fn grants(&self, query: GrantQuery) -> Result<bool, RingRpcError> {
        let mut members = vec![*query.reader.record_key()?.as_bytes()];
        if let Some(wallet) = query.wallet {
            let wallet = Member::owner_tag(wallet.as_array())?;
            let reader = query.reader.member()?;
            members.push(*Member::wallet_grant(&wallet, &reader)?.as_bytes());
        }
        let RecordsTip::Newest(records) = self.source.records_root(query.ring).await? else {
            return Err(GrantRefusal::RecordsUnavailable.into());
        };
        Ok(self
            .source
            .verified_openings(&records, &members)
            .await?
            .iter()
            .any(|read| read.listed(ListId::Reader)))
    }
}
