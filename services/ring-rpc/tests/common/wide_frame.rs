//! A frame past one transaction that the strict parser reads.

use bytemuck::Zeroable;
use custom_ring_interface::{
    cosign::ApprovalMask, storage::Revision, stream::slot_tag, AppMessage, CustomRingProof,
    FrameExtensions, InputTrees, InstructionTag, PlainGroth16Proof, RingMode, RingOutput, RingRail,
    RingTransactData, SlotBody, OUTPUT_RECORD_LEN,
};
use spr_interface::instruction::TreeContext;

/// Two inputs, two recipient slots and one long application message, under `tag`.
pub fn wide_frame(tag: u8) -> Vec<u8> {
    let rail = RingRail::of(
        InstructionTag::try_from(tag).expect("a transfer tag"),
        RingMode::Confidential,
    )
    .expect("a transfer tag");
    let proof = CustomRingProof::zeroed();
    let spp_proof = PlainGroth16Proof::zeroed();
    let field = [7; 32];
    let nullifiers = [[1; 32], [2; 32]];
    let salt = [3; 16];
    let record = [4; OUTPUT_RECORD_LEN];
    let keys = [5; 64];
    let message = vec![6; 6000];
    let output = RingOutput {
        hash: &field,
        owner_tag: slot_tag(field),
        body: SlotBody::Recipient(&record),
        record: &record,
    };
    let mut data = RingTransactData {
        rail,
        n_in: 2,
        n_out: 2,
        proof: &proof,
        tracking_revision: Revision::from(1),
        own_revision: None,
        policy: None,
        spl_withdrawal_owners: &[],
        approval: ApprovalMask::default(),
        no_spend: false,
        public_owners: false,
        expiry_unix_ts: 1_800_000_000,
        tx_viewing_u: &field,
        salt: &salt,
        extensions: FrameExtensions {
            messages: vec![AppMessage {
                view_tag: &field,
                data: &message,
            }],
            ..FrameExtensions::default()
        },
        interface_transfers: Vec::new(),
        has_data: false,
        entry: false,
        wide_owners: false,
        outputs: vec![output, output],
        replies: None,
        sender: None,
        envelope: &[],
        recipient_keys: &keys,
        private_tx_hash: &field,
        anonymous: None,
        in_proof_owner: None,
        spp_proof: &spp_proof,
        nullifiers: &nullifiers,
        input_trees: InputTrees::One(TreeContext {
            utxo_tree_root_index: 1,
            nullifier_tree_root_index: 2,
        }),
    };
    let envelope = vec![8; data.audit_stream().expect("stream").envelope().len];
    data.envelope = &envelope;
    let mut frame = vec![tag];
    frame.extend(data.encode().expect("encode"));
    frame
}
