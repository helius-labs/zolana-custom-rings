//! Pins `test-vectors/registry/ring-records.json` for the Go circuits and the TS SDK.
//!
//! Each update is the ordered batch `process_update_ix` in `programs/storage/src/instructions/update.rs`
//! chains and proves. Read before `prover/circuits/registry/vectors_test.go` and
//! `sdk-libs/ts/test/protocol/encoding/ring-shared-vectors.test.ts`.

use custom_ring_interface::{
    key_catalog::apply_width,
    mint_policy_write,
    storage::{chain_start, RegistryId, Revision, StorageRegistry},
    storage_instruction::InitializeIxData,
    write_chain, RecordWrite, RecordWriteData, WriteRecordsIxData, MEMBER_REGISTRY_EMPTY_ROOT,
    QUAD_HEIGHT,
};
use serde::{Deserialize, Serialize};
use solana_address::Address;
use spr_hasher::primitives::{hash_bytes, solana_owner_identity};
use zolana_ring_member_registry::{
    MemberRecord, MemberRegistryTree, OpeningCheck, QuadPath, RecordOpening,
    RecordStatementContext, RecordTracking, RecordTree, RecordWriteProofInput, ZERO_SUBTREES,
};
use zolana_ring_policy::{ListChange, ListId, ListSet};

const VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/registry/ring-records.json"
);

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct RecordVectors {
    description: String,
    empty_root: String,
    zero_subtrees: Vec<String>,
    registry: String,
    updates: Vec<Update>,
    openings: Vec<Opening>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Update {
    name: String,
    /// The registry's revision the proof names, one per earlier update.
    revision: u64,
    /// Instruction order.
    writes: Vec<BatchWrite>,
    old_root: String,
    new_root: String,
    old_next_index: u64,
    new_next_index: u64,
    chain_start: String,
    chain_end: String,
    count: u64,
    statement_hash: String,
    /// The public apply key's write capacity, every update writes public lists.
    width: u8,
    /// One per write, instruction order.
    proof_inputs: Vec<WriteInput>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct BatchWrite {
    member: String,
    mask: u64,
    value: u64,
    entry_hash: String,
    /// The chain after the write.
    chain: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct WriteInput {
    member: String,
    mask: u64,
    value: u64,
    exists: bool,
    old_next: String,
    old_lists: u64,
    slot: Path,
    low: Record,
    low_path: Path,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Record {
    member: String,
    next: String,
    lists: u64,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Path {
    index: u64,
    siblings: Vec<Vec<String>>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Opening {
    member: String,
    root: String,
    present: bool,
    /// The member's record, or the low record bracketing an absent member.
    record: Record,
    path: Path,
}

/// A list write with no mint settings, as `Update` instruction data carries it.
fn list_write(member: [u8; 32], set: ListSet, clear: ListSet) -> RecordWriteData {
    RecordWriteData {
        mint_policy: mint_policy_write(None),
        member,
        lists: WriteRecordsIxData::new(ListChange { set, clear }.check().expect("list write")),
    }
}

fn identity(signer: &[u8; 32]) -> [u8; 32] {
    solana_owner_identity(signer).expect("owner identity")
}

fn lists(lists: &[ListId]) -> ListSet {
    ListSet::of(lists)
}

fn signer(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn asset(seed: u8) -> [u8; 32] {
    hash_bytes(&[seed; 32]).expect("asset field")
}

struct Registry {
    tree: Option<MemberRegistryTree>,
    address: Address,
    revision: u64,
    state: StorageRegistry,
}

impl Registry {
    fn new(address: Address) -> Self {
        Self {
            tree: Some(MemberRegistryTree::new().expect("tree")),
            address,
            revision: 0,
            state: StorageRegistry::new(
                address,
                &InitializeIxData {
                    registry_id: RegistryId::default(),
                    grace_slots: [0; 8],
                    ring_id: [0; 32],
                    tracking_registry: Address::default(),
                },
            ),
        }
    }

    /// Folds `batch` as `process_update_ix` does and moves the tree by it.
    fn update(&mut self, name: &str, batch: &[RecordWriteData]) -> Update {
        // 1. The program reads every write through `storage_entry`, the leaf write the proof hashes.
        let entries: Vec<RecordWrite> = batch
            .iter()
            .map(|write| write.storage_entry().expect("storage write"))
            .collect();
        // 2. Every update starts its own chain at the registry and revision, a proof for another
        // registry or an applied revision then binds another chain.
        let chain_start =
            chain_start(&self.address, Revision::from(self.revision)).expect("chain start");
        let mut chain = chain_start;
        let mut writes = Vec::with_capacity(entries.len());
        for entry in &entries {
            chain = write_chain(&chain, entry).expect("chain");
            writes.push(BatchWrite {
                member: hex::encode(entry.member),
                mask: entry.mask,
                value: entry.value,
                entry_hash: hex::encode(entry.hash().expect("entry hash")),
                chain: hex::encode(chain),
            });
        }
        // 3. The tree replays the same writes into the apply proof inputs and must reach the same chain end.
        let applied = self
            .tree
            .take()
            .expect("tree")
            .apply(chain_start, &entries)
            .expect("update");
        self.tree = Some(applied.tree);
        let inputs = applied.proof;
        assert_eq!(inputs.chain_end, chain);
        let statement = inputs
            .statement(RecordStatementContext {
                registry: &self.state,
                asset_writes: &[],
                tracking: RecordTracking::Public,
            })
            .expect("statement");
        self.state.roots[0].hash = inputs.new_root;
        self.state.next_index = statement.new_next_index.to_le_bytes();
        let revision = self.revision;
        self.revision += 1;
        Update {
            name: name.to_string(),
            revision,
            writes,
            old_root: hex::encode(inputs.old_root),
            new_root: hex::encode(inputs.new_root),
            old_next_index: inputs.old_next_index,
            new_next_index: inputs.new_next_index,
            chain_start: hex::encode(inputs.chain_start),
            chain_end: hex::encode(inputs.chain_end),
            count: statement.count,
            statement_hash: hex::encode(statement.hash().expect("statement hash")),
            width: apply_width(statement.count),
            proof_inputs: inputs.writes.iter().map(write_input).collect(),
        }
    }

    fn opening(&self, member: &[u8; 32]) -> Opening {
        let tree = self.tree.as_ref().expect("tree");
        let root = tree.root().expect("root");
        let opening = tree.opening(member).expect("opening");
        let check = OpeningCheck {
            opening: &opening,
            root: &root,
            member,
        };
        assert!(check.verify().is_ok());
        let (present, record, path) = match opening {
            RecordOpening::Present { record, path } => (true, record, path),
            RecordOpening::Absent { low, path } => (false, low, path),
        };
        Opening {
            member: hex::encode(member),
            root: hex::encode(root),
            present,
            record: record_vector(&record),
            path: path_vector(&path),
        }
    }
}

fn write_input(input: &RecordWriteProofInput) -> WriteInput {
    WriteInput {
        member: hex::encode(input.entry.member),
        mask: input.entry.mask,
        value: input.entry.value,
        exists: input.exists,
        old_next: hex::encode(input.old_next),
        old_lists: input.old_lists,
        slot: path_vector(&input.slot),
        low: record_vector(&input.low),
        low_path: path_vector(&input.low_path),
    }
}

fn record_vector(record: &MemberRecord) -> Record {
    Record {
        member: hex::encode(record.member),
        next: hex::encode(record.next),
        lists: record.lists,
    }
}

fn path_vector(path: &QuadPath) -> Path {
    Path {
        index: path.index,
        siblings: path
            .siblings
            .iter()
            .map(|level| level.iter().map(hex::encode).collect())
            .collect(),
    }
}

fn compute_vectors() -> RecordVectors {
    use ListId::{Allow, Approval, Block, Frozen, Reader, RingViewing};
    let address = Address::new_from_array([0x52; 32]);
    let mut registry = Registry::new(address);
    let none = ListSet::EMPTY;
    let authority = registry.update(
        "authority_inserts_after_a_relink",
        &[
            list_write(identity(&signer(0x21)), lists(&[Allow]), none),
            list_write(asset(0x31), lists(&[Allow, Reader]), none),
            list_write(identity(&signer(0x22)), lists(&[Block]), none),
        ],
    );
    let members = registry.update(
        "member_writes_updates_and_no_op",
        &[
            list_write(identity(&signer(0x21)), lists(&[RingViewing]), none),
            list_write(identity(&signer(0x24)), none, lists(&[RingViewing])),
            list_write(identity(&signer(0x21)), none, lists(&[RingViewing])),
        ],
    );
    let member_writes =
        (0x40..0x48).map(|seed| list_write(identity(&signer(seed)), lists(&[RingViewing]), none));
    let authority_writes = (0x50..0x58).map(|seed| {
        let member = match seed % 2 {
            0 => identity(&signer(seed)),
            _ => identity(&signer(seed - 0x10)),
        };
        list_write(member, lists(&[Frozen, Approval]), lists(&[Allow]))
    });
    let full = registry.update(
        "full_batch_of_member_and_authority_writes",
        &member_writes.chain(authority_writes).collect::<Vec<_>>(),
    );
    let openings = [
        identity(&signer(0x21)),
        asset(0x31),
        identity(&signer(0x24)),
    ]
    .iter()
    .map(|member| registry.opening(member))
    .collect();
    RecordVectors {
        description:
            "Ordered Update batches of the storage program and the 4-ary member record tree \
                      they move. A write is the RecordWriteData the batch carries, read through \
                      storage_entry, with entry hash Poseidon(CRQW, member, mask, value, \
                      mint_policy_write, withdrawal_threshold, limits_0, limits_1, limits_2). \
                      Each update folds chain(p) = Poseidon(chain(p - 1), entry_p) from \
                      chain(-1) = chain_start = HashChain4(CRAP, hash_bytes(registry), revision), \
                      the revision counting earlier updates from zero. proof_inputs hold the \
                      apply circuit's inputs per write. Paths list three siblings per level, leaf \
                      level first, in ascending child order. Produced by \
                      program-libs/member-registry/tests/ring_records_vector.rs."
                .to_string(),
        empty_root: hex::encode(MEMBER_REGISTRY_EMPTY_ROOT),
        zero_subtrees: ZERO_SUBTREES[..=QUAD_HEIGHT]
            .iter()
            .map(hex::encode)
            .collect(),
        registry: hex::encode(address.as_array()),
        updates: vec![authority, members, full],
        openings,
    }
}

#[test]
fn ring_records_vector() {
    let committed: RecordVectors =
        serde_json::from_str(&std::fs::read_to_string(VECTORS).expect("vector file"))
            .expect("vector json");
    assert_eq!(committed, compute_vectors());
}

#[test]
#[ignore = "rewrites test-vectors/registry/ring-records.json"]
fn write_ring_records_vector() {
    let json = serde_json::to_string_pretty(&compute_vectors()).expect("json");
    std::fs::write(VECTORS, json + "\n").expect("write vector file");
}
