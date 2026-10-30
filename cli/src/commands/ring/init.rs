//! `init`, every step skipped when the chain already holds it, so a rerun resumes.

use anyhow::{bail, ensure, Context as _, Result};
use custom_ring_interface::{RingRole, RingRoles};
use custom_ring_sdk::{
    CustomRingConfig, InitialPolicy, Initialize, ListRegistry, PolicyTable, PolicyUpdate,
    RingError, RingKind, SourceOwner, UpdatePolicy,
};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signer::Signer;
use spr_keypair::X25519Pubkey;
use zolana_ring_client::rpc::{read_auditor_pubkey, write_auditor_pubkey};
use zolana_ring_policy::{ListId, RuleTable};

use crate::{
    catalogue,
    config::{expand_tilde, ModeName},
    deploy, file, line,
    policy::{self, CompiledPolicy, PolicySpec},
    status, Context, InitArgs, Trust,
};

const PRESENT: &str = "already present";
const CREATED: &str = "created";
const NEEDS_UPGRADE_AUTHORITY: &str = "the upgrade authority keypair signs `Initialize`";
const POLICY_DRIFT: &str =
    "the pinned policy differs from ring.toml, `zolana-ring policy set` replaces the table";
const PARTIAL_INIT: &str =
    "the ring config exists without the policy or SPP registration `Initialize` creates";

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KeySelection {
    file_present: bool,
    hosted_rpc: bool,
    local_auditor: bool,
    configured: Option<X25519Pubkey>,
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyChoice {
    File,
    Chain(X25519Pubkey),
    RingRpc,
}

/// A file the service did not write must not be pinned against a hosted rpc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a local auditor key file against a hosted ring rpc")]
struct StrayLocalKey;

/// `Initialize` names the four role keys, the upgrade authority holds none it does not name.
#[must_use]
struct ConfigCreation<'a> {
    deployer: Option<&'a Keypair>,
    /// Holds the policy role and pays.
    config_authority: &'a Keypair,
    auditor_pk: X25519Pubkey,
    policy: Option<&'a CompiledPolicy>,
    mode: ModeName,
    existing: Option<&'a CustomRingConfig>,
}

/// `Initialize` over the records Ring RPC holds.
#[must_use]
struct RingInitialization<'a> {
    deployer: &'a Keypair,
    config_authority: &'a Keypair,
    roles: RingRoles,
    auditor_pk: X25519Pubkey,
    kind: RingKind,
    policy: Option<&'a CompiledPolicy>,
}

#[must_use]
struct PolicyPin<'a> {
    authority: &'a Keypair,
    policy: &'a CompiledPolicy,
    outcome: &'static str,
}

pub fn run(ctx: &Context, args: InitArgs) -> Result<()> {
    let key_file = ctx.path(&expand_tilde(&args.auditor_pubkey_file)?);
    let compile = |spec: &PolicySpec| spec.compile(ctx.config.target);
    let policy = ctx.config.policy.as_ref().map(compile).transpose()?;
    let config_authority = ctx.funded_authority()?;
    let existing = ctx.block(ctx.ring.config(ctx.chain()))?;
    // Only the upgrade authority creates the config, the policy authority pins the rest.
    let upgrade_authority = match existing {
        Some(_) => None,
        None => Some(ctx.config.upgrade_authority()?),
    };
    if let Some(deployer) = upgrade_authority.as_ref() {
        let program = ctx.ring.program_id();
        let data = deploy::program_data(ctx)?
            .with_context(|| format!("program {program} is not deployed, run `deploy` first"))?;
        let authority = data.upgrade_authority.with_context(|| {
            format!("program {program} is immutable and has no config, nothing can create one")
        })?;
        ensure!(
            authority == deployer.pubkey(),
            "program {program} is upgradeable by {authority}, ring.toml names {}",
            deployer.pubkey()
        );
    }
    let urls = ctx.config.urls();
    let selection = KeySelection {
        file_present: key_file.exists(),
        hosted_rpc: !urls.ring_rpc_is_local(),
        local_auditor: args.local_auditor,
        configured: existing.as_ref().map(|config| config.auditor_pubkey),
    };
    let choice = selection.decide().with_context(|| {
        format!(
            "{} holds an auditor key, but the ring rpc at {} is not on this machine and holds its own. Pinning this key means only a ring rpc serving it can ever open the ring. Delete the file to take the service's key, or pass --local-auditor to keep it",
            key_file.display(),
            urls.ring_rpc
        )
    })?;
    let auditor_pk = match choice {
        KeyChoice::File => read_auditor_pubkey(&key_file)?,
        KeyChoice::Chain(auditor_pk) => {
            if key_file.exists() {
                let file = read_auditor_pubkey(&key_file)?;
                ensure!(
                    file == auditor_pk,
                    "{} holds auditor {}, the ring config pins {}. Delete the stale file",
                    key_file.display(),
                    hex::encode(file.as_bytes()),
                    hex::encode(auditor_pk.as_bytes())
                );
            }
            auditor_pk
        }
        KeyChoice::RingRpc => {
            let genesis_hash = ctx.rpc().genesis_hash()?;
            let authority = upgrade_authority
                .as_ref()
                .context(NEEDS_UPGRADE_AUTHORITY)?;
            let trust = ctx.trust(match args.trust_ring_rpc {
                true => Trust::Unpinned,
                false => Trust::Refuse,
            })?;
            ctx.ring_rpc()
                .release_auditor_key(ctx.ring.program_id(), genesis_hash, authority)?
                .require(trust)?
        }
    };
    let ring = ctx.ring;
    let created = ConfigCreation {
        deployer: upgrade_authority.as_ref(),
        config_authority,
        auditor_pk,
        policy: policy.as_ref(),
        mode: ctx.config.mode,
        existing: existing.as_ref(),
    }
    .send(ctx)?;
    let ring_config = ctx.ring_config()?;
    let records = ring_config.account().records;
    let policy = match &policy {
        None if created == CREATED => "records only, created",
        None => "records only",
        Some(policy) => PolicyPin {
            authority: config_authority,
            policy,
            outcome: created,
        }
        .send(ctx)?,
    };
    let spp_ring = match ctx.block(ring.registration(ctx.chain()))? {
        Some(_) if created == CREATED => "registered",
        Some(_) => PRESENT,
        None => bail!(PARTIAL_INIT),
    };
    // Written after the chain agrees, so a failed init leaves no file a rerun takes for a local key.
    if choice == KeyChoice::RingRpc {
        write_auditor_pubkey(&key_file, &auditor_pk)?;
        line(
            "auditor pk",
            format_args!(
                "{} (from {}, written to {})",
                hex::encode(auditor_pk.as_bytes()),
                urls.ring_rpc,
                key_file.display()
            ),
        );
    }
    line("config", created);
    status::print_roles(&ring_config.roles);
    line("records", format_args!("{records} {created}"));
    line("policy", policy);
    line("spp ring", spp_ring);
    status::announce(&ctx.config);
    Ok(())
}

impl KeySelection {
    /// A config wins, its key is fixed and a rerun must not touch the service.
    fn decide(self) -> Result<KeyChoice, StrayLocalKey> {
        match self.configured {
            Some(auditor_pk) => Ok(KeyChoice::Chain(auditor_pk)),
            None if !self.file_present => Ok(KeyChoice::RingRpc),
            None if self.hosted_rpc && !self.local_auditor => Err(StrayLocalKey),
            None => Ok(KeyChoice::File),
        }
    }
}

impl ConfigCreation<'_> {
    fn send(self, ctx: &Context) -> Result<&'static str> {
        let policy_key = self.config_authority.pubkey();
        if let Some(config) = self.existing {
            ensure!(
                config.auditor_pubkey == self.auditor_pk && config.roles.policy == policy_key,
                "ring config exists under policy authority {} with auditor {}, ring.toml names another operator",
                config.roles.policy,
                hex::encode(config.auditor_pubkey.as_bytes())
            );
            // The tier is immutable, transfer dispatches on it.
            ensure!(
                config.has_policy == self.policy.is_some(),
                "the ring is deployed as {}, ring.toml now selects the other tier, redeploy is not a tier change",
                if config.has_policy { "a policy ring" } else { "audit-only" }
            );
            ensure!(
                ModeName::of(config.mode) == self.mode,
                "ring.toml selects the {} mode, the deployed config has another, redeploy is not a mode change",
                self.mode
            );
            return Ok(PRESENT);
        }
        let deployer = self.deployer.context(NEEDS_UPGRADE_AUTHORITY)?;
        let role_key = |role| -> Result<Address> {
            Ok(file::read_or_create_keypair(&ctx.role_keypair_path(role)?)?.pubkey())
        };
        let roles = RingRoles {
            admin: role_key(RingRole::Admin)?,
            policy: policy_key,
            pauser: role_key(RingRole::Pauser)?,
            cosign_admin: role_key(RingRole::CosignAdmin)?,
        };
        let kind = match (self.mode, self.policy.is_some()) {
            (ModeName::Confidential, false) => RingKind::AuditOnly,
            (ModeName::Confidential, true) => RingKind::Policy,
            (ModeName::Anonymous, false) => RingKind::Anonymous,
            (ModeName::Anonymous, true) => RingKind::AnonymousPolicy,
        };
        RingInitialization {
            deployer,
            config_authority: self.config_authority,
            roles,
            auditor_pk: self.auditor_pk,
            kind,
            policy: self.policy,
        }
        .send(ctx)?;
        Ok(CREATED)
    }
}

impl RingInitialization<'_> {
    fn send(self, ctx: &Context) -> Result<()> {
        let target = self.config_authority.pubkey();
        let records = ctx
            .ring_rpc()
            .create_records_registry(ctx.ring_rpc_target()?, self.deployer)?;
        let empty = RuleTable::empty();
        let (rules, shared_sources) = match self.policy {
            Some(policy) => {
                for (list, curator) in &policy.shared_sources {
                    catalogue::check_curator(ctx, *curator, *list)?;
                }
                (
                    &policy.rules,
                    policy::curator_sources(ctx, &policy.shared_sources)?,
                )
            }
            None => (&empty, Vec::new()),
        };
        let instruction = |shared_sources: &[(ListId, Address)]| {
            Initialize {
                ring: ctx.ring,
                payer: target,
                authority: self.deployer.pubkey(),
                auditor_pubkey: self.auditor_pk,
                kind: self.kind,
                roles: self.roles,
                policy: Some(InitialPolicy {
                    records,
                    table: PolicyTable {
                        rules,
                        shared_sources,
                    },
                }),
            }
            .instruction()
        };
        // Curators past the transaction size are pointed one by one by the policy pin.
        let initialize = match instruction(&shared_sources) {
            Err(RingError::TransactionTooLarge { .. }) if !shared_sources.is_empty() => {
                instruction(&[])?
            }
            result => result?,
        };
        ctx.send(&[self.config_authority, self.deployer], &[initialize])?;
        Ok(())
    }
}

impl PolicyPin<'_> {
    /// Sources are pointed only over rows that agree, a drifted table stays untouched.
    fn send(self, ctx: &Context) -> Result<&'static str> {
        let Self {
            authority,
            policy,
            outcome,
        } = self;
        for (list, curator) in &policy.shared_sources {
            catalogue::check_curator(ctx, *curator, *list)?;
        }
        let shared_sources = policy::curator_sources(ctx, &policy.shared_sources)?;
        let pinned = policy::pinned_if_any(ctx)?.context(PARTIAL_INIT)?;
        policy::verify_rows(policy, &pinned).context(POLICY_DRIFT)?;
        crate::records::write_mint_policies(ctx, &policy::mint_changes(ctx, policy)?)?;
        let mut pointed = false;
        for ((list, curator), (_, registry)) in policy.shared_sources.iter().zip(&shared_sources) {
            let outcome =
                if pinned.account.registry_for(*list) == Some(ListRegistry::Curator(*registry)) {
                    PRESENT
                } else {
                    let point = UpdatePolicy {
                        ring: ctx.ring,
                        authority: authority.pubkey(),
                        update: PolicyUpdate::Source {
                            list_id: *list,
                            source: SourceOwner::Curator(*registry),
                        },
                    }
                    .instruction()?;
                    ctx.send(&[authority], &[point])?;
                    pointed = true;
                    CREATED
                };
            line(
                list.name(),
                format_args!("curator {} {outcome}", curator.program_id()),
            );
        }
        let pinned = if pointed {
            policy::pinned(ctx)?
        } else {
            pinned
        };
        policy::verify_sources(ctx, policy, &pinned).context(POLICY_DRIFT)?;
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNCONFIGURED: KeySelection = KeySelection {
        file_present: false,
        hosted_rpc: false,
        local_auditor: false,
        configured: None,
    };

    #[test]
    fn a_config_wins_over_the_file_and_the_service() {
        let pinned = spr_keypair::X25519Keypair::new().pubkey();
        for file_present in [true, false] {
            for hosted_rpc in [true, false] {
                for local_auditor in [true, false] {
                    let selection = KeySelection {
                        file_present,
                        hosted_rpc,
                        local_auditor,
                        configured: Some(pinned),
                    };
                    assert_eq!(selection.decide(), Ok(KeyChoice::Chain(pinned)));
                }
            }
        }
    }

    #[test]
    fn without_a_config_the_file_is_taken_only_where_the_service_wrote_it() {
        for hosted_rpc in [true, false] {
            for local_auditor in [true, false] {
                let selection = KeySelection {
                    hosted_rpc,
                    local_auditor,
                    ..UNCONFIGURED
                };
                assert_eq!(selection.decide(), Ok(KeyChoice::RingRpc));
            }
        }
        let file = KeySelection {
            file_present: true,
            ..UNCONFIGURED
        };
        assert_eq!(file.decide(), Ok(KeyChoice::File));
        let kept = KeySelection {
            local_auditor: true,
            ..file
        };
        assert_eq!(kept.decide(), Ok(KeyChoice::File));
        let hosted_kept = KeySelection {
            hosted_rpc: true,
            ..kept
        };
        assert_eq!(hosted_kept.decide(), Ok(KeyChoice::File));
        let hosted = KeySelection {
            hosted_rpc: true,
            ..file
        };
        assert_eq!(hosted.decide(), Err(StrayLocalKey));
    }
}
