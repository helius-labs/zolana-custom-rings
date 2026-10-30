//! The ring's accounts as the chain holds them, every read checked against its canonical address.

use custom_ring_interface::{CoSignScope, CoSigner, RingAccount, RingMode, RingPolicy, RingRoles};
use solana_account::Account;
use solana_address::Address;
use spr_client::AsyncRpc;
use spr_interface::{pda, state::RingConfig, BPF_LOADER_UPGRADEABLE_ID, RING_AUTH_PDA_SEED};
use spr_keypair::X25519Pubkey;
use zolana_ring_policy::{ring_id_field, RuleTable, SourceMap};

use crate::RingError;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CustomRing {
    program_id: Address,
}

/// The ring account, decoded once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomRingConfig {
    pub roles: RingRoles,
    pub auditor_pubkey: X25519Pubkey,
    /// A policy ring enforces its table, an audit-only ring proves only the audit statement.
    pub has_policy: bool,
    /// Selects the spend rail and the disclosure layout, `SetDelegate` moves Off to Registry.
    pub mode: RingMode,
    /// The classes some `CoSigner` record covers.
    pub co_signer_classes: Option<CoSignScope>,
    pub delegate: Option<Address>,
    pub created_slot: u64,
    account: Box<RingPolicy>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomRingCoSigner {
    pub signer: Address,
    pub scope: CoSignScope,
    account: CoSigner,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingRegistration {
    pub activated: bool,
    pub paused: bool,
    /// The delegate rail the activation enables.
    pub authority_rail: bool,
}

/// `None` for an absent account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingStatus {
    pub config: CustomRingConfig,
    pub registration: Option<RingRegistration>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedPolicy {
    pub table: RuleTable,
    pub sources: SourceMap,
    pub policy_hash: [u8; 32],
    pub curator: Option<Address>,
}

impl CustomRing {
    pub const fn new(program_id: Address) -> Self {
        Self { program_id }
    }

    pub const fn program_id(self) -> Address {
        self.program_id
    }

    /// `hash_bytes` of the program id, the ring id every statement and UTXO binds.
    pub fn ring_id(self) -> Result<[u8; 32], RingError> {
        Ok(ring_id_field(self.program_id.as_array())?)
    }

    fn pda(self, seeds: &[&[u8]]) -> (Address, u8) {
        Address::find_program_address(seeds, &self.program_id)
    }

    pub fn policy_pda(self) -> Address {
        self.pda(&[RingPolicy::SEED]).0
    }

    pub fn co_signer_pda(self, signer: &Address) -> Address {
        self.pda(&[CoSigner::SEED, signer.as_ref()]).0
    }

    /// SPP stores the ring config here and requires it as the signer of ring CPIs.
    pub fn ring_auth_pda(self) -> Address {
        self.pda(&[RING_AUTH_PDA_SEED]).0
    }

    pub fn program_data_pda(self) -> Address {
        Address::find_program_address(
            &[self.program_id.as_ref()],
            &Address::new_from_array(BPF_LOADER_UPGRADEABLE_ID),
        )
        .0
    }

    /// The canonical account of `A`, `None` when absent.
    pub async fn read<A: RingAccount>(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<Option<A>, RingError> {
        let (address, bump) = self.pda(&[A::SEED]);
        let Some(account) = rpc.get_account(address).await? else {
            return Ok(None);
        };
        A::decode(&account.owner, &self.program_id, &account.data)
            .filter(|state| state.bump() == bump)
            .map(Some)
            .ok_or(RingError::InvalidAccount { address })
    }

    pub async fn config(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<Option<CustomRingConfig>, RingError> {
        let Some(account) = self.read::<RingPolicy>(rpc).await? else {
            return Ok(None);
        };
        CustomRingConfig::new(Box::new(account), self.policy_pda()).map(Some)
    }

    pub async fn require_config(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<CustomRingConfig, RingError> {
        self.config(rpc).await?.ok_or(RingError::MissingRingConfig)
    }

    pub async fn policy(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<Option<Box<RingPolicy>>, RingError> {
        Ok(self.read::<RingPolicy>(rpc).await?.map(Box::new))
    }

    pub async fn require_policy(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<Box<RingPolicy>, RingError> {
        self.policy(rpc).await?.ok_or(RingError::MissingRingPolicy)
    }

    /// `None` on an audit-only ring.
    pub async fn pinned_policy(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<Option<PinnedPolicy>, RingError> {
        let config = self.require_config(rpc).await?;
        if !config.has_policy {
            return Ok(None);
        }
        PinnedPolicy::of(config.account()).map(Some)
    }

    /// `None` when `signer` holds no record.
    pub async fn co_signer(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
        signer: &Address,
    ) -> Result<Option<CustomRingCoSigner>, RingError> {
        let (address, bump) = self.pda(&[CoSigner::SEED, signer.as_ref()]);
        let Some(account) = rpc.get_account(address).await? else {
            return Ok(None);
        };
        CoSigner::decode(&account.owner, &self.program_id, &account.data)
            .filter(|record| record.bump() == bump && record.signer == *signer)
            .and_then(|record| {
                Some(CustomRingCoSigner {
                    signer: record.signer,
                    scope: record.scope()?,
                    account: record,
                })
            })
            .map(Some)
            .ok_or(RingError::InvalidAccount { address })
    }

    pub async fn registration(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<Option<RingRegistration>, RingError> {
        let (address, bump) = self.pda(&[RING_AUTH_PDA_SEED]);
        let Some(account) = rpc.get_account(address).await? else {
            return Ok(None);
        };
        let config = spp_ring_config(&account, self.program_id, bump)
            .ok_or(RingError::InvalidAccount { address })?;
        Ok(Some(RingRegistration {
            activated: config.is_activated(),
            paused: config.is_paused(),
            authority_rail: config.enabled(),
        }))
    }

    /// SPP's deposit, transfer and merge rails refuse a ring not registered, not activated or paused.
    pub async fn require_active(self, rpc: &(impl AsyncRpc + ?Sized)) -> Result<(), RingError> {
        match self.registration(rpc).await? {
            None => Err(RingError::RingNotRegistered),
            Some(registration) if !registration.activated => Err(RingError::RingNotActivated),
            Some(registration) if registration.paused => Err(RingError::RingPaused),
            Some(_) => Ok(()),
        }
    }

    pub async fn status(self, rpc: &(impl AsyncRpc + ?Sized)) -> Result<RingStatus, RingError> {
        Ok(RingStatus {
            config: self.require_config(rpc).await?,
            registration: self.registration(rpc).await?,
        })
    }
}

impl CustomRingCoSigner {
    pub fn account(&self) -> &CoSigner {
        &self.account
    }
}

impl CustomRingConfig {
    fn new(account: Box<RingPolicy>, address: Address) -> Result<Self, RingError> {
        let invalid = || RingError::InvalidAccount { address };
        Ok(Self {
            roles: account.roles,
            auditor_pubkey: X25519Pubkey::from_bytes(account.auditor_pubkey)
                .map_err(|_| invalid())?,
            has_policy: account.has_policy(),
            mode: account.mode()?,
            co_signer_classes: account.co_signers.covered(),
            delegate: account.delegate().copied(),
            created_slot: account.created_slot(),
            account,
        })
    }

    pub fn account(&self) -> &RingPolicy {
        &self.account
    }
}

impl PinnedPolicy {
    /// The stored table and sources, refused unless they reproduce the pinned hash.
    pub fn of(policy: &RingPolicy) -> Result<Self, RingError> {
        let policy_hash = *policy.policy_hash()?;
        let sources = policy.source_map()?;
        let table = policy.rule_table()?;
        if table.hash(&sources)? != policy_hash {
            return Err(RingError::HashMismatch);
        }
        Ok(Self {
            table,
            sources,
            policy_hash,
            curator: policy.curator(),
        })
    }

    pub fn matches(&self, rules: &RuleTable) -> Result<(), RingError> {
        if rules.encode() != self.table.encode() {
            return Err(RingError::TableMismatch);
        }
        Ok(())
    }
}

fn spp_ring_config(account: &Account, program_id: Address, bump: u8) -> Option<RingConfig> {
    (account.owner == pda::shielded_pool_program_id() && account.data.len() == RingConfig::SIZE)
        .then(|| {
            bytemuck::try_from_bytes::<RingConfig>(&account.data)
                .ok()
                .copied()
        })
        .flatten()
        .filter(|config| {
            config.has_discriminator() && config.program_id == program_id && config.bump == bump
        })
}
