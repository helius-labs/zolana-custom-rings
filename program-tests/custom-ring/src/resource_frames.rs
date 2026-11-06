use custom_ring_interface::{AppMessage, RingPolicy, RingTransactData, MAX_CPI_DATA_LEN};
use solana_message::v1::MAX_TRANSACTION_SIZE;
use spr_interface::instruction::TransactProof;

/// An inline frame never passes the transaction it rides in, a bound above every settled frame.
const FRAME_CEILING: usize = MAX_TRANSACTION_SIZE;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Payload {
    Base,
    MaximumBytes,
    MaximumMessages,
}

pub struct MaximumPayload<'a, 'data> {
    pub data: &'a mut RingTransactData<'data>,
    pub policy: &'a RingPolicy,
    pub message: &'data [u8],
    pub view_tag: &'data [u8; 32],
}

impl MaximumPayload<'_, '_> {
    /// `false` when the frame passes the ceiling before any payload, no inline transfer carries it.
    #[must_use]
    pub fn fill(self, payload: Payload) -> bool {
        assert!(payload != Payload::Base);
        let Self {
            data,
            policy,
            message,
            view_tag,
        } = self;
        data.extensions.messages.push(AppMessage {
            view_tag,
            data: &[],
        });
        let mut compact = data.encode().unwrap().len() + 1;
        let mut expanded = data
            .spp_instruction_data_under(policy, TransactProof::zeroed())
            .unwrap()
            .len();
        if compact > FRAME_CEILING {
            return false;
        }
        if payload == Payload::MaximumMessages {
            let empty = data.extensions.messages[0];
            data.extensions.messages.push(empty);
            let compact_stride = data.encode().unwrap().len() + 1 - compact;
            let expanded_stride = data
                .spp_instruction_data_under(policy, TransactProof::zeroed())
                .unwrap()
                .len()
                - expanded;
            data.extensions.messages.pop();
            let extra = ((FRAME_CEILING - compact) / compact_stride)
                .min((MAX_CPI_DATA_LEN - expanded) / expanded_stride)
                .min(usize::from(u8::MAX) - 2 - usize::from(data.sender.is_some()));
            data.extensions.messages.extend((0..extra).map(|_| empty));
            compact += extra * compact_stride;
            expanded += extra * expanded_stride;
        }
        let remaining = FRAME_CEILING
            .checked_sub(compact)
            .unwrap()
            .min(MAX_CPI_DATA_LEN.checked_sub(expanded).unwrap());
        data.extensions.messages[0].data = &message[..remaining];
        let compact = data.encode().unwrap().len() + 1;
        let expanded = data
            .spp_instruction_data_under(policy, TransactProof::zeroed())
            .unwrap()
            .len();
        assert!(compact == FRAME_CEILING || expanded == MAX_CPI_DATA_LEN);
        true
    }
}
