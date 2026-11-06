use custom_ring_interface::RingMode;
use spr_interface::{pda, state::default_tree_fees};
use spr_tree::TreeFeeSchedule;

use crate::tests::support::{Chain, RingSettings, TREE_ID};
use crate::written_tree_fees;

#[tokio::test]
async fn written_trees_pay_each_schedule_once() {
    let default = default_tree_fees();
    let raised = TreeFeeSchedule {
        fee_per_tree: default.fee_per_tree + 1,
        ..default
    };
    let chain = Chain::ring(RingSettings::new(RingMode::Confidential)).with_tree_fees(7, raised);
    let (input, output) = (pda::tree(TREE_ID), pda::tree(7));

    assert_eq!(
        written_tree_fees(&chain, [input, output, input])
            .await
            .unwrap(),
        default.fee_per_tree + raised.fee_per_tree
    );
    assert_eq!(
        written_tree_fees(&chain, [input, input]).await.unwrap(),
        default.fee_per_tree
    );
    assert!(written_tree_fees(&chain, [pda::tree(8)]).await.is_err());
}
