//! The ring's operating controls, each read back from the chain after a change.

use std::path::Path;

use anyhow::{anyhow, bail, ensure, Context as _, Result};
use custom_ring_interface::RingRole;
use custom_ring_sdk::{
    ClearCoSigner, CoSignScope, CustomRingCoSigner, RingMode, RingRegistration, SetCoSigner,
    SetDelegate,
};
use solana_address::Address;
use solana_signer::Signer;
use spr_keypair::X25519Keypair;
use zolana_ring_policy::ListId;

use crate::{
    config::{Base58Address, CoSignClass, CoSignerSpec},
    file, keys, line,
    list::{ListChange, ListUpdate, Subject},
    policy,
    ui::{self, icon},
    CoSignerCommand, Context, DelegateCommand, ReaderCommand, AUDITOR_KEY_FILE,
};

#[must_use]
pub(crate) struct DualControl {
    pub cosigner: Option<Address>,
    pub delegate: Option<Address>,
}

#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Setup {
    NoConfig,
    AuditOnly,
    PolicyUnpinned,
    PolicyPinned,
}

pub fn cosigner(ctx: &Context, command: CoSignerCommand) -> Result<()> {
    match command {
        CoSignerCommand::Set {
            signer,
            scope,
            threshold,
        } => {
            let spec = match signer {
                Some(signer) => CoSignerSpec {
                    key: Base58Address(signer),
                    scope,
                    thresholds: threshold,
                },
                None => ctx
                    .config
                    .cosigner
                    .clone()
                    .context("no signer given and ring.toml has no [cosigner] table")?,
            };
            let scope = spec
                .scope()
                .context("the co-signer gates no operation class")?;
            let thresholds = &spec.thresholds;
            check_thresholds(scope, thresholds)?;
            DualControl {
                cosigner: Some(spec.key.0),
                delegate: ctx.ring_config()?.delegate,
            }
            .check()?;
            let payer = ctx.funded_authority()?;
            let cosign_admin = ctx.role_keypair(RingRole::CosignAdmin)?;
            let set = SetCoSigner {
                ring: ctx.ring,
                payer: payer.pubkey(),
                authority: cosign_admin.pubkey(),
                signer: spec.key.0,
                scope,
            }
            .instruction()?;
            let current = crate::records::mint_policies(ctx)?;
            let mut desired = current.clone();
            for policy in desired.values_mut() {
                policy.withdrawal_threshold = 0;
            }
            let mut seen = std::collections::BTreeSet::new();
            for row in thresholds {
                let member = *zolana_ring_policy::Member::asset(&row.mint.0)?.as_bytes();
                ensure!(seen.insert(member), "duplicate withdrawal threshold mint");
                desired.entry(member).or_default().withdrawal_threshold = row.above;
            }
            desired.retain(|member, policy| {
                *policy != current.get(member).copied().unwrap_or_default()
            });
            // Set the co-signer before applying its threshold records.
            ctx.send(&[payer, &cosign_admin], &[set])?;
            crate::records::write_mint_policies(ctx, &desired)?;
            line("co-signer", format_args!("{} set", spec.key));
            print_cosigners(ctx, Some(spec.key.0))
        }
        CoSignerCommand::Clear { signer } => {
            let signer = cosigner_key(ctx, signer)?;
            ensure!(
                ctx.block(ctx.ring.co_signer(ctx.chain(), &signer))?
                    .is_some(),
                "{signer} holds no co-signer record"
            );
            let payer = ctx.funded_authority()?;
            let cosign_admin = ctx.role_keypair(RingRole::CosignAdmin)?;
            let clear = ClearCoSigner {
                ring: ctx.ring,
                authority: cosign_admin.pubkey(),
                signer,
                rent_recipient: payer.pubkey(),
            }
            .instruction();
            ctx.send(&[payer, &cosign_admin], &[clear])?;
            line("co-signer", format_args!("{signer} cleared"));
            print_cosigners(ctx, None)
        }
        CoSignerCommand::Show { signer } => {
            let signer = signer.or_else(|| ctx.config.cosigner.as_ref().map(|spec| spec.key.0));
            print_cosigners(ctx, signer)
        }
    }
}

/// The named key, else the `[cosigner]` key of ring.toml.
fn cosigner_key(ctx: &Context, signer: Option<Address>) -> Result<Address> {
    match signer {
        Some(signer) => Ok(signer),
        None => Ok(ctx
            .config
            .cosigner
            .as_ref()
            .context("no signer given and ring.toml has no [cosigner] table")?
            .key
            .0),
    }
}

/// The classes some record covers, then `signer`'s record and the withdrawal thresholds.
fn print_cosigners(ctx: &Context, signer: Option<Address>) -> Result<()> {
    let Some(classes) = ctx.ring_config()?.co_signer_classes else {
        line("co-signer", "none");
        return Ok(());
    };
    line("co-signed classes", class_names(classes));
    if let Some(signer) = signer {
        match ctx.block(ctx.ring.co_signer(ctx.chain(), &signer))? {
            Some(cosigner) => print_cosigner(&cosigner),
            None => line("co-signer", format_args!("{signer} holds no record")),
        }
    }
    for (member, policy) in crate::records::mint_policies(ctx)? {
        if policy.withdrawal_threshold != 0 {
            line(
                "withdrawal threshold",
                format_args!(
                    "{} above {}",
                    hex::encode(member),
                    policy.withdrawal_threshold
                ),
            );
        }
    }
    Ok(())
}

pub(crate) fn class_names(scope: CoSignScope) -> String {
    let names: Vec<_> = CoSignClass::ALL
        .into_iter()
        .filter(|class| scope.contains(class.scope()))
        .map(CoSignClass::as_str)
        .collect();
    names.join(",")
}

pub(crate) fn print_cosigner(cosigner: &CustomRingCoSigner) {
    line("co-signer", cosigner.signer);
    line("scope", class_names(cosigner.scope));
}

/// A grant of a granted reader and a revoke of an absent one send nothing.
pub fn reader(ctx: &Context, command: ReaderCommand) -> Result<()> {
    let (change, reader) = match command {
        ReaderCommand::Grant { reader } => (ListChange::Set, reader),
        ReaderCommand::Revoke { reader } => (ListChange::Clear, reader),
    };
    let subject = Subject {
        member: reader.member()?,
        label: format!("reader {reader}"),
    };
    let outcomes = ListUpdate {
        authority: ctx.authority()?,
        list_id: ListId::Reader,
        subjects: core::slice::from_ref(&subject),
        change,
    }
    .send(ctx)?;
    let [outcome] = <[_; 1]>::try_from(outcomes).map_err(|_| anyhow!("one reader, one outcome"))?;
    line("reader", format_args!("{reader} {outcome}"));
    Ok(())
}

pub fn pause(ctx: &Context, paused: bool) -> Result<()> {
    let registration = require_initialized(ctx)?;
    let outcome = match (registration.paused == paused, paused) {
        (true, true) => "already paused",
        (true, false) => "already open",
        (false, _) => {
            let payer = ctx.funded_authority()?;
            let pauser = ctx.role_keypair(RingRole::Pauser)?;
            let set = match paused {
                true => ctx.ring.pause(pauser.pubkey())?,
                false => ctx.ring.resume(pauser.pubkey())?,
            };
            ctx.send(&[payer, &pauser], &[set])?;
            ["resumed", "paused"][usize::from(paused)]
        }
    };
    line("spp ring", outcome);
    let program = ctx.ring.program_id();
    match paused {
        true => ui::heading(
            icon::PAUSE,
            &format!("ring {program} refuses every operation"),
        ),
        false => ui::heading(icon::RESUME, &format!("ring {program} is open")),
    }
    Ok(())
}

pub fn delegate(ctx: &Context, command: DelegateCommand) -> Result<()> {
    match command {
        DelegateCommand::Set { delegate_keypair } => {
            let delegate = file::read_keypair(&ctx.path(&delegate_keypair))?;
            let config = ctx.ring_config()?;
            if let Some(current) = config.delegate {
                bail!("the ring's delegate {current} is permanent");
            }
            DualControl {
                cosigner: ctx.config.cosigner.as_ref().map(|spec| spec.key.0),
                delegate: Some(delegate.pubkey()),
            }
            .check()?;
            ensure!(
                config.has_policy && config.mode != RingMode::Anonymous,
                "a delegate escrows keys only on a confidential policy ring"
            );
            ring_auditor_key(ctx, Path::new(AUDITOR_KEY_FILE))?;
            let payer = ctx.funded_authority()?;
            let admin = ctx.role_keypair(RingRole::Admin)?;
            let set = SetDelegate {
                ring: ctx.ring,
                authority: admin.pubkey(),
                delegate: delegate.pubkey(),
            };
            ctx.send(&[payer, &admin, &delegate], &[set.instruction()])?;
            line("delegate", format_args!("{} set", delegate.pubkey()));
            ui::warn("every later transfer escrows its output keys");
        }
        DelegateCommand::Show => {}
        DelegateCommand::Move(args) => return crate::delegate::run_move(ctx, *args),
    }
    match ctx.ring_config()?.delegate {
        Some(delegate) => line("delegate", delegate),
        None => line("delegate", "none"),
    }
    Ok(())
}

/// The auditor read key opens recovery material, it cannot authorize a transfer.
pub(crate) fn ring_auditor_key(ctx: &Context, path: &Path) -> Result<X25519Keypair> {
    let config = ctx.ring_config()?;
    let path = ctx.path(path);
    let auditor = keys::read(&path)?;
    ensure!(
        auditor.pubkey() == config.auditor_pubkey,
        "{} does not hold the ring auditor read key {}",
        path.display(),
        hex::encode(config.auditor_pubkey.as_bytes())
    );
    Ok(auditor)
}

pub(crate) fn require_initialized(ctx: &Context) -> Result<RingRegistration> {
    let setup = match ctx.block(ctx.ring.config(ctx.chain()))? {
        None => Setup::NoConfig,
        Some(config) if !config.has_policy => Setup::AuditOnly,
        Some(_) => match policy::pinned_if_any(ctx)? {
            Some(_) => Setup::PolicyPinned,
            None => Setup::PolicyUnpinned,
        },
    };
    let registration = ctx.block(ctx.ring.registration(ctx.chain()))?;
    registration.filter(|_| setup.complete()).with_context(|| {
        format!(
            "ring {} is not initialized, run `init` first",
            ctx.ring.program_id()
        )
    })
}

impl Setup {
    #[must_use]
    const fn complete(self) -> bool {
        matches!(self, Self::AuditOnly | Self::PolicyPinned)
    }
}

impl DualControl {
    pub(crate) fn check(self) -> Result<()> {
        if let (Some(cosigner), Some(delegate)) = (self.cosigner, self.delegate) {
            ensure!(
                cosigner != delegate,
                "{delegate} is the ring's delegate, dual control needs a co-signer other than it"
            );
        }
        Ok(())
    }
}

fn check_thresholds(scope: CoSignScope, thresholds: &[crate::config::ThresholdSpec]) -> Result<()> {
    ensure!(
        thresholds.is_empty() || scope.contains(CoSignScope::WITHDRAWALS),
        "co-signer thresholds bound withdrawals, add the withdrawals class to the scope"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn co_signer_thresholds_need_the_withdrawal_scope() {
        let row = [crate::config::ThresholdSpec {
            mint: Base58Address(Address::default()),
            above: 5,
        }];
        assert!(check_thresholds(CoSignScope::TRANSFERS, &row).is_err());
        let withdrawals = CoSignScope::TRANSFERS | CoSignScope::WITHDRAWALS;
        assert!(check_thresholds(withdrawals, &row).is_ok());
        assert!(check_thresholds(CoSignScope::TRANSFERS, &[]).is_ok());
    }

    #[test]
    fn the_delegate_never_co_signs_its_own_moves() {
        let (key, other) = (
            Address::new_from_array([1; 32]),
            Address::new_from_array([2; 32]),
        );
        let control = |cosigner, delegate| DualControl { cosigner, delegate }.check();
        assert!(control(Some(key), Some(key)).is_err());
        assert!(control(Some(key), Some(other)).is_ok());
        assert!(control(None, Some(key)).is_ok());
        assert!(control(Some(key), None).is_ok());
    }

    #[test]
    fn setup_completes_with_the_policy_only_on_a_policy_ring() {
        assert!(Setup::AuditOnly.complete());
        assert!(Setup::PolicyPinned.complete());
        assert!(!Setup::PolicyUnpinned.complete());
        assert!(!Setup::NoConfig.complete());
    }

    #[test]
    fn a_spec_scope_unions_its_classes() {
        let spec = CoSignerSpec {
            key: Base58Address(solana_address::Address::default()),
            scope: vec![CoSignClass::Deposits, CoSignClass::Withdrawals],
            thresholds: Vec::new(),
        };
        assert_eq!(
            spec.scope(),
            Some(CoSignScope::DEPOSITS | CoSignScope::WITHDRAWALS)
        );
        let empty = CoSignerSpec {
            scope: Vec::new(),
            ..spec
        };
        assert_eq!(empty.scope(), None);
    }
}
