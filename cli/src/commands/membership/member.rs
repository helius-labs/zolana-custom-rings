//! `key`, the member's nullifier key escrowed in its record.

use anyhow::{ensure, Result};
use custom_ring_sdk::{CustomRing, KeyRegistration, MemberRecords, RingMode, WalletRecordUpdate};
use solana_signer::Signer;
use spr_client::{BlockingIndexer, BlockingRpc};
use spr_keypair::ShieldedKeypair;
use zolana_ring_client::RingIndexer;
use zolana_ring_policy::Member;

use crate::{line, records, Context, KeyCommand, Zolana};

const SEAL_PROMPT: &str = "seal the member key to the ring auditor and register it?";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Plan {
    AlreadyRegistered,
    Enroll,
    Declined,
}

#[must_use]
pub(crate) struct KeyEnrolment<'a> {
    pub members: &'a [&'a ShieldedKeypair],
}

pub fn key(ctx: &Context, command: KeyCommand) -> Result<()> {
    let KeyCommand::Register = command;
    let config = ctx.ring_config()?;
    ensure!(
        config.mode != RingMode::Anonymous,
        "an anonymous ring escrows no key, its auditor opens every note"
    );
    let sender = ctx.sender()?;
    let member = ShieldedKeypair::from_keypair(&sender)?;
    line("member", sender.pubkey());
    let registered = registered(ctx.ring, &ctx.zolana, &member)?;
    match plan(registered, || ctx.ask_yes(SEAL_PROMPT, true))? {
        Plan::AlreadyRegistered => line("key", "already registered"),
        Plan::Declined => line("key", "not registered"),
        Plan::Enroll => {
            register(ctx, &member)?;
            line("key", "registered");
        }
    }
    Ok(())
}

impl KeyEnrolment<'_> {
    pub(crate) fn ensure(self, ctx: &Context) -> Result<()> {
        for member in self.members {
            let outcome = if registered(ctx.ring, &ctx.zolana, member)? {
                "already registered"
            } else {
                register(ctx, member)?;
                "registered"
            };
            line("member key", format_args!("{} {outcome}", member.pubkey()));
        }
        Ok(())
    }
}

fn register(ctx: &Context, member: &ShieldedKeypair) -> Result<()> {
    let registration = ctx.block(
        KeyRegistration {
            ring: ctx.ring,
            member: member.shielded_address()?,
            authority: member,
        }
        .prove(ctx.ring_client()),
    )?;
    let update = WalletRecordUpdate::new(ctx.record_update_target()?, member.pubkey())?
        .with_escrow(registration)?
        .sign(member)?;
    ctx.ring_rpc().apply_record_update(update)?;
    Ok(())
}

fn plan(registered: bool, confirm: impl FnOnce() -> Result<bool>) -> Result<Plan> {
    Ok(match registered {
        true => Plan::AlreadyRegistered,
        false if confirm()? => Plan::Enroll,
        false => Plan::Declined,
    })
}

/// Only the member's own nullifier key escrowed under the current root counts.
fn registered<R: BlockingRpc, I: BlockingIndexer + RingIndexer>(
    ring: CustomRing,
    zolana: &Zolana<R, I>,
    keys: &ShieldedKeypair,
) -> Result<bool> {
    let member = Member::owner_tag(keys.pubkey().as_array())?;
    let read = records::read_one(
        zolana,
        MemberRecords {
            ring,
            members: &[member],
        },
    )?;
    let nullifier_pubkey = keys.shielded_address()?.nullifier_pubkey;
    Ok(read.escrowed(&nullifier_pubkey)?.is_some())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU8, Ordering};

    use custom_ring_interface::{EscrowKey, QueueEntry};
    use custom_ring_sdk::RingError;
    use spr_client::{ClientError, Rpc, WitnessReader};
    use spr_keypair::X25519Keypair;
    use zolana_ring_client::{AuditError, NullifierKeyEnvelope};
    use zolana_ring_client::{RingIndexer, RingIndexerError, RingRpcError};
    use zolana_ring_indexer::rpc::{
        GetStorageMemberOpeningsRequest, GetStorageMemberOpeningsResponse, RingMemberOpening,
    };
    use zolana_ring_member_registry::MemberRegistryTree;

    use super::*;
    use crate::{
        records::fixtures::{ring, tree, zolana, IndexerAnswer, PolicyRpc},
        ui::{Answer, Ask, Scripted},
    };

    fn member() -> ShieldedKeypair {
        ShieldedKeypair::new_ed25519().expect("keypair")
    }

    fn identity(member: &ShieldedKeypair) -> [u8; 32] {
        *Member::owner_tag(member.pubkey().as_array())
            .unwrap()
            .as_bytes()
    }

    struct Stub(GetStorageMemberOpeningsResponse);

    impl WitnessReader for Stub {}

    impl Rpc for Stub {}

    impl RingIndexer for Stub {
        fn get_storage_member_openings(
            &self,
            _request: GetStorageMemberOpeningsRequest,
        ) -> Result<GetStorageMemberOpeningsResponse, RingIndexerError> {
            Ok(self.0.clone())
        }
    }

    /// `key_holder`'s nullifier key escrowed in `member`'s record.
    struct Escrowed<'a> {
        member: &'a ShieldedKeypair,
        key_holder: &'a ShieldedKeypair,
    }

    struct Served {
        rpc: PolicyRpc,
        indexer: Stub,
    }

    impl Escrowed<'_> {
        fn served(self) -> Served {
            let envelope = NullifierKeyEnvelope::new(
                &self.key_holder.nullifier_key,
                &X25519Keypair::new().pubkey(),
            )
            .unwrap();
            let escrow = EscrowKey {
                nullifier_pk: &envelope.nullifier_pk,
                ciphertext: &envelope.sealed.ciphertext,
            };
            let member = identity(self.member);
            let tree = tree(&[QueueEntry::escrow(member, &escrow).unwrap()]);
            let answer = IndexerAnswer {
                tree: &tree,
                member: &member,
                sealed: Some(&envelope.sealed),
            }
            .openings();
            Served {
                rpc: PolicyRpc::of(tree),
                indexer: Stub(answer),
            }
        }
    }

    impl Served {
        fn registered(self, member: &ShieldedKeypair) -> Result<bool> {
            registered(ring(), &zolana(self.rpc, self.indexer), member)
        }
    }

    fn ring_error(result: Result<bool>) -> RingError {
        match result.expect_err("refused").downcast::<RingError>() {
            Ok(error) => error,
            Err(error) => panic!("not a ring error: {error:?}"),
        }
    }

    #[test]
    fn a_registered_key_skips_the_seal_without_prompting() {
        let member = member();
        let served = Escrowed {
            member: &member,
            key_holder: &member,
        }
        .served();
        assert!(served.registered(&member).expect("registered"));
        let plan = plan(true, || panic!("an enrolled member is not asked"));
        assert_eq!(plan.expect("plan"), Plan::AlreadyRegistered);
    }

    #[test]
    fn an_unregistered_member_enrolls_only_on_confirmation() {
        let member = member();
        let empty = MemberRegistryTree::new().unwrap();
        let absent = IndexerAnswer {
            tree: &empty,
            member: &identity(&member),
            sealed: None,
        }
        .openings();
        let client = zolana(PolicyRpc::of(empty), Stub(absent));
        assert!(!registered(ring(), &client, &member).expect("registered"));
        let mut yes = Scripted::new([Answer::Yes(true)]);
        assert_eq!(
            plan(false, || yes.confirm(SEAL_PROMPT, true)).expect("plan"),
            Plan::Enroll
        );
        let mut no = Scripted::new([Answer::Yes(false)]);
        assert_eq!(
            plan(false, || no.confirm(SEAL_PROMPT, true)).expect("plan"),
            Plan::Declined
        );
    }

    #[test]
    fn a_lagging_registry_is_polled_until_it_answers() {
        struct Lagging(AtomicU8, GetStorageMemberOpeningsResponse);
        impl WitnessReader for Lagging {}
        impl Rpc for Lagging {}
        impl RingIndexer for Lagging {
            fn get_storage_member_openings(
                &self,
                _request: GetStorageMemberOpeningsRequest,
            ) -> Result<GetStorageMemberOpeningsResponse, RingIndexerError> {
                if self.0.fetch_add(1, Ordering::Relaxed) == 0 {
                    return Err(RingRpcError::RegistryOutOfSync.into());
                }
                Ok(self.1.clone())
            }
        }
        let member = member();
        let empty = MemberRegistryTree::new().unwrap();
        let absent = IndexerAnswer {
            tree: &empty,
            member: &identity(&member),
            sealed: None,
        }
        .openings();
        let client = zolana(PolicyRpc::of(empty), Lagging(AtomicU8::new(0), absent));
        assert!(!registered(ring(), &client, &member).expect("registered"));
        assert_eq!(client.indexer().0.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn a_changed_registry_root_is_refetched_before_retrying() {
        struct Advanced(AtomicU8, [u8; 32], GetStorageMemberOpeningsResponse);
        impl WitnessReader for Advanced {}
        impl Rpc for Advanced {}
        impl RingIndexer for Advanced {
            fn get_storage_member_openings(
                &self,
                request: GetStorageMemberOpeningsRequest,
            ) -> Result<GetStorageMemberOpeningsResponse, RingIndexerError> {
                if self.0.fetch_add(1, Ordering::Relaxed) == 0 {
                    assert_eq!(request.expected_root.0, self.1);
                    return Err(RingRpcError::RegistryRootChanged.into());
                }
                assert_eq!(request.expected_root.0, self.2.root.root.0);
                Ok(self.2.clone())
            }
        }
        let member = member();
        let other = *Member::owner_tag(&[5; 32]).unwrap().as_bytes();
        let advanced = tree(&[QueueEntry {
            mint_policy: Default::default(),
            member: other,
            mask: 1,
            value: 1,
            escrow_key: [0; 32],
        }]);
        let answer = IndexerAnswer {
            tree: &advanced,
            member: &identity(&member),
            sealed: None,
        }
        .openings();
        let first = MemberRegistryTree::new().unwrap();
        let first_root = zolana_ring_member_registry::RecordTree::root(&first).unwrap();
        let rpc = PolicyRpc::of(first).advancing_to(advanced);
        let client = zolana(rpc, Advanced(AtomicU8::new(0), first_root, answer));
        assert!(!registered(ring(), &client, &member).expect("registered"));
        assert_eq!(client.indexer().0.load(Ordering::Relaxed), 2);
        assert_eq!(client.rpc().reads(), 2);
    }

    #[test]
    fn a_forged_record_cannot_skip_key_enrollment() {
        let member = member();
        let forged = |forge: fn(&mut RingMemberOpening)| {
            let mut served = Escrowed {
                member: &member,
                key_holder: &member,
            }
            .served();
            forge(&mut served.indexer.0.openings[0]);
            served.registered(&member)
        };
        assert!(matches!(
            ring_error(forged(|opening| opening.path.siblings[0][0].0[31] ^= 1)),
            RingError::Audit(AuditError::InvalidMemberRegistry)
        ));
        let sealed = forged(|opening| opening.record.ciphertext.as_mut().unwrap().0[31] ^= 1);
        assert!(!sealed.unwrap(), "a forged sealed key escrows nothing");
        assert!(matches!(
            ring_error(forged(|opening| opening.record.member.0[31] ^= 1)),
            RingError::Audit(AuditError::InvalidMemberRegistry)
        ));
    }

    #[test]
    fn another_escrowed_nullifier_key_does_not_enroll_the_sender() {
        let member = member();
        let mut different_key = ShieldedKeypair::new_ed25519().unwrap();
        different_key.signing_key = member.signing_key.clone();
        let served = Escrowed {
            member: &member,
            key_holder: &different_key,
        }
        .served();
        assert!(!served.registered(&member).unwrap());
    }

    #[test]
    fn a_transport_failure_is_not_read_as_unregistered() {
        struct Down;
        impl WitnessReader for Down {}
        impl Rpc for Down {}
        impl RingIndexer for Down {
            fn get_storage_member_openings(
                &self,
                _request: GetStorageMemberOpeningsRequest,
            ) -> Result<GetStorageMemberOpeningsResponse, RingIndexerError> {
                Err(ClientError::IndexerUnavailable("down".to_owned()).into())
            }
        }
        let empty = MemberRegistryTree::new().unwrap();
        assert!(matches!(
            ring_error(registered(
                ring(),
                &zolana(PolicyRpc::of(empty), Down),
                &member()
            )),
            RingError::Client(_)
        ));
    }
}
