use custom_ring_interface::{
    key_catalog::RingCircuit, policy_withdrawal_hash, verifying_key, CustomRingError, PolicyKey,
    PolicyStatement, RingProof,
};
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use spr_account_checks::AccountIterator;
use spr_interface::N_PUBLIC_SLOTS;
use zolana_ring_policy::{registry_field, SourceMap};

use crate::{loader::load_registry, parse, VerifyPolicyIxData};

const MEMBER_POLICY_CIRCUIT: RingCircuit = RingCircuit::MemberPolicy {
    outputs: 2,
    withdrawals: 0,
    own_only: true,
};

pub fn process_verify_policy_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: &VerifyPolicyIxData = parse(data)?;
    let mut accounts = AccountIterator::new(accounts);
    let registry_account = accounts.next_account("registry")?;
    let instance =
        registry_field(registry_account.address().as_array()).map_err(CustomRingError::from)?;
    let registry = load_registry(program_id, registry_account)?;
    let root = registry.root(ix.revision, Clock::get()?.slot)?;
    let sources = SourceMap::new(
        &ix.table
            .referenced()
            .iter()
            .map(|list| (list, [0; 32]))
            .collect::<Vec<_>>(),
    )
    .map_err(CustomRingError::from)?;
    ix.table.validate(&sources).map_err(CustomRingError::from)?;
    // The rule hash authenticates the supplied table only.
    let statement = PolicyStatement {
        key: PolicyKey::Member { anonymous: false },
        private_tx_hash: &ix.action,
        policy_hash: &ix.table.hash(&sources).map_err(CustomRingError::from)?,
        ring_id: &instance,
        approval_required: false,
        key_escrow: false,
        own_root: &root,
        curator_root: &[0; 32],
        sender: &ix.sender,
        public_assets: &[[0; 32]; N_PUBLIC_SLOTS],
        public_amounts: &[[0; 32]; N_PUBLIC_SLOTS],
        withdrawal_hash: &policy_withdrawal_hash(&[]).map_err(CustomRingError::from)?,
    };
    RingProof {
        proof: &ix.proof,
        statement: statement.hash().map_err(CustomRingError::from)?,
        key: verifying_key(MEMBER_POLICY_CIRCUIT).ok_or(CustomRingError::UnsupportedCircuit)?,
    }
    .verify()
}
