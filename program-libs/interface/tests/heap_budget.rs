//! Host allocation counts do not establish SBF heap bounds.

#[path = "../../../program-tests/custom-ring/src/resource_frames.rs"]
mod resource_frames;

use resource_frames::{MaximumPayload, Payload};

mod frames;
mod ring_policy;

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use custom_ring_interface::{
    cosign::{ApprovalMask, CoSignOperation},
    key_catalog::{FrameKey, RecordPools, TransferShape, TransferSpend},
    storage::Revision,
    AnonymousProofData, CustomRingError, InProofOwner, PolicyProof, PublicLeg, PublicSlots,
    Replies, RingRail, RingTransactData, SlotBody, MAX_CPI_DATA_LEN, MIN_REPLY_LEN,
};
use frames::Fixture;
use ring_policy::config;
use spr_interface::instruction::{InterfaceTransfer, TransactProof};
use spr_interface::shape::SPP_SUPPORTED_SHAPES;

/// The codec phases of one invocation, parse, the public legs and the SPP expansion, modeled as Pinocchio's bump that reclaims nothing.
const BUDGET: usize = 12 * 1024;

const MINT: [u8; 32] = [0x11; 32];

/// Pinocchio's forward bump allocator, the cursor word first, nothing reclaimed.
struct BumpModel;

static POS: AtomicUsize = AtomicUsize::new(0);
static ON: AtomicBool = AtomicBool::new(false);

fn bump(layout: Layout) {
    if !ON.load(Ordering::Relaxed) {
        return;
    }
    let _ = POS.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |pos| {
        let start = (pos + layout.align() - 1) & !(layout.align() - 1);
        Some(start + layout.size())
    });
}

unsafe impl GlobalAlloc for BumpModel {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        bump(layout);
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        bump(layout);
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        bump(unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) });
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: BumpModel = BumpModel;

struct Arena;

impl Arena {
    fn start() {
        POS.store(core::mem::size_of::<usize>(), Ordering::Relaxed);
        ON.store(true, Ordering::Relaxed);
    }

    fn used() -> usize {
        POS.load(Ordering::Relaxed)
    }

    fn stop() {
        ON.store(false, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy)]
enum Legs {
    Sol,
    Spl,
}

#[derive(Clone, Copy)]
struct Widest {
    rail: RingRail,
    inputs: usize,
    outputs: usize,
    legs: usize,
    kind: Legs,
    policy: bool,
    thresholds: bool,
    entry: bool,
    in_proof: bool,
    replies: bool,
    payload: Payload,
}

impl Widest {
    fn name(&self) -> String {
        format!(
            "{} {}x{} {}{} {}{}{}{}",
            self.rail,
            self.inputs,
            self.outputs,
            self.legs,
            match self.kind {
                Legs::Sol => " sol",
                Legs::Spl => " spl",
            },
            if self.policy { "policy" } else { "audit-only" },
            if self.thresholds { " thresholds" } else { "" },
            if self.entry {
                " entry"
            } else if self.in_proof {
                " in-proof"
            } else if self.replies {
                " replies"
            } else {
                ""
            },
            match self.payload {
                Payload::Base => "",
                Payload::MaximumBytes => " maximum bytes",
                Payload::MaximumMessages => " maximum messages",
            },
        )
    }
}

/// The owners the widest frames reference.
struct Pool {
    owners: Vec<[u8; 32]>,
    message: Vec<u8>,
}

/// Each key at the widest SPP shape of every output width it serves on `rail`.
fn served(rail: RingRail, entry: bool) -> Vec<(TransferShape, usize, usize)> {
    let mut served = Vec::new();
    for wide in [false, true] {
        for spp in SPP_SUPPORTED_SHAPES
            .iter()
            .filter(|spp| rail.supports(**spp))
        {
            let (inputs, outputs) = (spp.n_inputs(), spp.n_outputs());
            let key = FrameKey {
                rail,
                inputs,
                outputs,
                spends_default_ring: entry,
                wide,
            };
            let Some(shape) = key.shape() else {
                continue;
            };
            let same_key =
                |case: &&mut (TransferShape, usize, usize)| case.0 == shape && case.2 == outputs;
            match served.iter_mut().find(same_key) {
                Some(case) => case.1 = case.1.max(inputs),
                None => served.push((shape, inputs, outputs)),
            }
        }
    }
    served
}

fn cases() -> Vec<Widest> {
    let mut cases = Vec::new();
    for (shape, inputs, outputs) in served(RingRail::Confidential, false) {
        let base = Widest {
            rail: RingRail::Confidential,
            inputs,
            outputs,
            legs: usize::from(shape.withdrawals),
            kind: Legs::Sol,
            policy: true,
            thresholds: false,
            entry: false,
            in_proof: false,
            replies: false,
            payload: Payload::Base,
        };
        cases.push(base);
        cases.push(Widest {
            kind: Legs::Spl,
            ..base
        });
        cases.push(Widest {
            in_proof: true,
            ..base
        });
        cases.push(Widest {
            policy: false,
            thresholds: true,
            ..base
        });
    }
    for (shape, inputs, outputs) in served(RingRail::Anonymous, false) {
        let base = Widest {
            rail: RingRail::Anonymous,
            inputs,
            outputs,
            legs: usize::from(shape.withdrawals),
            kind: Legs::Sol,
            policy: true,
            thresholds: false,
            entry: false,
            in_proof: false,
            replies: false,
            payload: Payload::Base,
        };
        cases.push(base);
        cases.push(Widest {
            kind: Legs::Spl,
            ..base
        });
        cases.push(Widest {
            policy: false,
            thresholds: true,
            ..base
        });
        cases.push(Widest {
            replies: true,
            ..base
        });
    }
    for (shape, inputs, outputs) in served(RingRail::Anonymous, true) {
        let base = Widest {
            rail: RingRail::Anonymous,
            inputs,
            outputs,
            legs: usize::from(shape.withdrawals),
            kind: Legs::Sol,
            policy: true,
            thresholds: false,
            entry: true,
            in_proof: false,
            replies: false,
            payload: Payload::Base,
        };
        cases.push(base);
        cases.push(Widest {
            policy: false,
            thresholds: true,
            ..base
        });
    }
    cases.push(Widest {
        rail: RingRail::Delegate,
        inputs: 4,
        outputs: 4,
        legs: 0,
        kind: Legs::Sol,
        policy: false,
        thresholds: false,
        entry: false,
        in_proof: false,
        replies: false,
        payload: Payload::Base,
    });
    let maximum_payloads: Vec<_> = cases
        .iter()
        .flat_map(|case| {
            [Payload::MaximumBytes, Payload::MaximumMessages].map(|payload| Widest {
                payload,
                replies: case.rail == RingRail::Anonymous,
                ..*case
            })
        })
        .collect();
    cases.extend(maximum_payloads);
    cases
}

fn frame<'a>(fixture: &'a Fixture, pool: &'a Pool, case: Widest) -> Option<RingTransactData<'a>> {
    let anonymous = case.rail == RingRail::Anonymous;
    let mut data = fixture.base(case.rail, case.inputs as u8, case.outputs as u8);
    data.entry = case.entry;
    data.wide_owners = TransferSpend {
        rail: case.rail,
        inputs: case.inputs,
        outputs: case.outputs,
        spends_default_ring: case.entry,
        legs: case.legs,
        owners: 0,
        pools: RecordPools::default(),
        wide: false,
    }
    .fitted()
    .wide;
    if case.policy || case.thresholds {
        data.approval = ApprovalMask::OUTFLOW;
        data.own_revision = Some(Revision::from(7));
    }
    data.interface_transfers = (0..case.legs)
        .map(|leg| {
            let amount = 1_000 + leg as u64;
            match case.kind {
                Legs::Sol => InterfaceTransfer::SolWithdrawal { amount },
                Legs::Spl => InterfaceTransfer::SplWithdrawal {
                    amount,
                    spl_interface_bump: 254,
                },
            }
        })
        .collect();
    if data.own_revision.is_some() {
        data.spl_withdrawal_owners = match case.kind {
            Legs::Sol => &[],
            Legs::Spl => &pool.owners[..case.legs],
        };
    }
    if case.policy {
        data.policy = Some(PolicyProof {
            curator_revision: (!anonymous).then(|| Revision::from(3)),
        });
    }
    let exit_slot = (case.rail != RingRail::Delegate).then_some(case.outputs - 1);
    data.outputs = (0..case.outputs)
        .map(|slot| match (anonymous, Some(slot) == exit_slot) {
            (_, true) => fixture.exit(slot, &fixture.payload),
            (true, false) => fixture.tagged(slot),
            (false, false) => fixture.recipient(slot),
        })
        .collect();
    if anonymous {
        data.sender = fixture.sender(case.outputs);
        data.anonymous = Some(AnonymousProofData {
            commitment: &fixture.bytes[20],
            commitment_pok: &fixture.bytes[21],
            default_owner_tag: (!case.entry).then_some(&fixture.bytes[22]),
        });
    }
    if case.replies {
        // Every slot but the exit carries a body.
        let bodies = case.outputs - 1;
        data.replies = Some(
            Replies::new(
                MIN_REPLY_LEN as u16,
                &fixture.replies[..MIN_REPLY_LEN * bodies],
            )
            .unwrap(),
        );
    }
    if case.in_proof {
        data.in_proof_owner = Some(InProofOwner {
            owner: &fixture.bytes[16],
            commitment: &fixture.bytes[20],
            commitment_pok: &fixture.bytes[21],
        });
    }
    if case.payload != Payload::Base {
        data.has_data = true;
        for (slot, output) in data.outputs.iter_mut().enumerate() {
            output.body = match output.body {
                SlotBody::Recipient(_) => SlotBody::Recipient(&fixture.extended_bodies[slot]),
                SlotBody::Exit(_) => SlotBody::Exit(&fixture.extended_bodies[slot]),
            };
        }
        data = fixture.with_audit_stream(data);
        let filled = MaximumPayload {
            data: &mut data,
            policy: &config(),
            message: &pool.message,
            view_tag: &fixture.bytes[30],
        }
        .fill(case.payload);
        if !filled {
            return None;
        }
    }
    Some(fixture.with_audit_stream(data))
}

struct Phases {
    parse: usize,
    legs: usize,
    spp: usize,
}

/// The codec phases in the program's order, the public legs built as the program builds them.
fn measure(compact: &[u8], rail: RingRail) -> Phases {
    let config = config();
    Arena::start();
    let parsed = RingTransactData::parse(compact, rail).unwrap();
    let parse = Arena::used();
    let data = parsed.data();
    let slots = PublicSlots::fold(data.interface_transfers.iter().map(|transfer| {
        Ok::<_, CustomRingError>(PublicLeg {
            transfer: *transfer,
            mint: transfer.mint_account_position().map(|_| MINT),
        })
    }))
    .unwrap();
    let demand = CoSignOperation {
        spends_note: !data.no_spend,
        public_legs: slots.classes(),
        approval: data.approval,
    }
    .demand();
    let legs = Arena::used();
    let spp_data = data
        .spp_instruction_data_under(&config, TransactProof::zeroed())
        .unwrap();
    let spp = Arena::used();
    Arena::stop();
    assert!(
        demand.classes.bits() != 0
            && slots.len() <= spr_interface::N_PUBLIC_SLOTS
            && spp_data.len() > 1
    );
    Phases { parse, legs, spp }
}

#[test]
fn host_codec_allocations_cover_frames_up_to_the_transaction_ceiling() {
    let fixture = Fixture::new();
    let pool = Pool {
        owners: vec![[0x70; 32]; spr_interface::MAX_INTERFACE_TRANSFERS],
        message: vec![0x71; MAX_CPI_DATA_LEN],
    };
    let mut report = Vec::new();
    let committed = fixture.cases();
    let widest: Vec<(String, RingTransactData<'_>)> = cases()
        .into_iter()
        .filter_map(|case| Some((case.name(), frame(&fixture, &pool, case)?)))
        .collect();
    for (name, data) in committed
        .iter()
        .map(|(name, data)| (name.to_string(), data))
        .chain(widest.iter().map(|(name, data)| (name.clone(), data)))
    {
        let compact = data.encode().unwrap();
        let phases = measure(&compact, data.rail);
        report.push((name, compact.len(), phases));
    }
    for (name, bytes, phases) in &report {
        println!(
            "{name:<48} frame {bytes:>5} parse {:>5} legs {:>5} spp {:>5}",
            phases.parse, phases.legs, phases.spp
        );
    }
    let over: Vec<_> = report
        .iter()
        .filter(|(_, _, phases)| phases.spp > BUDGET)
        .map(|(name, _, phases)| format!("{name} takes {} of {BUDGET}", phases.spp))
        .collect();
    assert!(over.is_empty(), "{over:#?}");
}
