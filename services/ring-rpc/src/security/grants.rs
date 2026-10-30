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
    /// The wallet's owner identity, the member a merge names.
    member: Member,
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
    fn new(wallet: Address) -> Result<Self, RingRpcError> {
        Ok(Self {
            wallet,
            member: Member::owner_tag(wallet.as_array())?,
        })
    }

    pub(crate) fn activity(
        self,
        response: GetDecryptedTransactionsResponse,
    ) -> GetWalletActivityResponse {
        GetWalletActivityResponse {
            context: response.context,
            value: WalletActivityPage {
                items: response
                    .value
                    .items
                    .into_iter()
                    .filter_map(|item| WalletActivity::of(self.wallet, item))
                    .collect(),
                cursor: response.value.cursor,
            },
        }
    }
}

impl ReadScope {
    pub(crate) fn new(wallet: Option<Address>) -> Result<Self, RingRpcError> {
        Ok(match wallet {
            Some(wallet) => Self::Wallet(WalletScope::new(wallet)?),
            None => Self::Ring,
        })
    }

    pub(crate) fn merges(self, page: &mut AuditedMergesPage) {
        if let Self::Wallet(scope) = self {
            page.opened
                .retain(|merge| merge.owner_member.0 == *scope.member.as_bytes());
            page.unresolved.clear();
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
        let reader = query.reader.member()?;
        let mut members = vec![*reader.as_bytes()];
        if let Some(wallet) = query.wallet {
            let wallet = Member::owner_tag(wallet.as_array())?;
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
