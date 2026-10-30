use custom_ring_interface::RingMode;

use super::support::{account, keypair, program, ring, Chain, Registry, RingSettings};
use crate::{PinnedPolicy, RingError};

#[tokio::test]
async fn the_status_carries_the_pinned_registry() {
    let member = keypair(1);
    let client = Chain::ring(RingSettings {
        has_policy: true,
        ..RingSettings::new(RingMode::ConfidentialEscrow)
    })
    .with_registry(Registry::new(&[(&member, 1)]), &super::pipeline_rules())
    .client();
    let status = ring().status(client.zolana()).await.unwrap();
    let pinned = PinnedPolicy::of(status.registry.unwrap().account()).unwrap();
    assert_eq!(pinned.table, super::pipeline_rules());
}

#[tokio::test]
async fn a_config_with_an_unknown_mode_byte_is_an_invalid_account() {
    let settings = RingSettings::new(RingMode::Confidential);
    let mut config = settings.config();
    config.mode = 7;
    let chain = Chain::ring(settings).with(ring().config_pda(), account(program(), &config));
    assert!(matches!(
        ring().config(&chain).await,
        Err(RingError::InvalidAccount { address }) if address == ring().config_pda()
    ));
}
