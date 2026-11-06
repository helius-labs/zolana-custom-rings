/** The address ceiling of one compiled transaction, Rust `validation::address_ceiling`. */
import {
  TRANSACTION_SIZE_LIMIT as LIMIT_BYTES,
  type Address,
  type Bytes32,
  type Bytes33,
  type Instruction,
} from "@heliuslabs/spr/interface";
import {
  equalBytes,
  isZero,
  nullifierPdaAddress,
  ZERO_NULLIFIER_PK,
} from "@heliuslabs/spr/internal";
import type { ShieldedPublicKey } from "@heliuslabs/spr/keypair";
import type { ProofInputUtxo } from "@heliuslabs/spr/transaction";

import { RingError } from "../../protocol/error.js";
import { RingInstructionTag } from "../../protocol/transaction/instruction-tag.js";
import {
  MAX_CPI_DATA_LEN,
  ringRailOf,
  RingTransactData,
  type RingTransactConfig,
} from "../../protocol/transaction/transact.js";
import {
  MAX_TRANSACTION_ADDRESSES,
  MAX_TRANSACTION_INSTRUCTIONS,
  MAX_TRANSACTION_SIGNATURES,
  transactionSignatures,
  transactionSize,
  type TransactionSize,
} from "./compile.js";

const ZERO_POLICY: RingTransactConfig = Object.freeze({
  auditorPubkey: new Uint8Array(33) as Bytes33,
});

/** The message around the operation, setup compiles ahead of it in one transaction. */
export interface FitSigners {
  readonly payer: Address;
  /** Its signers and addresses join the count. */
  readonly setupInstructions?: readonly Instruction[];
}

export interface FitBudget {
  readonly computeUnitLimit: number;
  readonly priorityFeeLamports?: bigint;
}

/** What setup adds to the transaction it shares with the operation. */
export interface SetupEffect {
  readonly instructions: number;
  readonly signatures: number;
  readonly bytes: number;
  readonly addresses: number;
}

/** What the transaction costs against each ceiling, setup included. */
export interface Fit {
  readonly signatures: number;
  readonly bytes: number;
  readonly addresses: number;
  /** The data SPP receives on the transfer tags, absent on any other tag. */
  readonly cpiBytes?: number;
  readonly setup: SetupEffect;
}

/** One real input of the transaction, as SPP merge groups it. */
export interface SpentInput {
  readonly owner: ShieldedPublicKey;
  readonly asset: Address;
  readonly nullifierPublicKey: Bytes32;
  readonly dataHash?: Bytes32;
  readonly ringProgramId?: Address;
  readonly treeId: number;
  readonly nullifierPda: Address;
}

/** `FittedMerge`'s published inputs per kind of merge, a zero-key merge adds its signer. */
export interface MergeCapacity {
  readonly keyed: number;
  readonly zeroKey: number;
}

export interface MergeGroup {
  readonly owner: ShieldedPublicKey;
  readonly asset: Address;
  readonly nullifierPublicKey: Bytes32;
  readonly ringProgramId?: Address;
  readonly treeId: number;
  /** Positions in `inputs`. */
  readonly inputs: readonly number[];
}

export type CeilingDecision =
  | Readonly<{ kind: "inline"; size: TransactionSize }>
  /** `addresses` counts one nullifier PDA left per merged note. */
  | Readonly<{ kind: "mergeFirst"; groups: readonly MergeGroup[]; addresses: number }>;

export async function spentInputOf(input: ProofInputUtxo, tree: Address): Promise<SpentInput> {
  const { utxo } = input;
  return Object.freeze({
    owner: utxo.owner,
    asset: utxo.asset,
    nullifierPublicKey: input.nullifierPublicKey,
    ...(input.dataHash === undefined ? {} : { dataHash: input.dataHash }),
    ...(utxo.ringProgramId === undefined ? {} : { ringProgramId: utxo.ringProgramId }),
    treeId: input.treeId,
    nullifierPda: await nullifierPdaAddress(tree, input.nullifier()),
  });
}

/** Rust `TransactionFit`, the one acceptance rule of a final transaction, refusing CPI bytes, then signatures, instructions, bytes, addresses. */
export const TransactionFit = Object.freeze({
  of(instruction: Instruction, signers: FitSigners, budget: FitBudget): Fit {
    const cpiBytes = sppCpiBytes(instruction);
    checkCounts(instruction, signers);
    return accept({ form: instruction, signers, budget, cpiBytes });
  },
});

/** Rust `AddressCeiling::decide`, `RING_ADDRESS_CEILING` when merging every valid group falls short. */
export function decideAddressCeiling(
  input: Readonly<{
    payer: Address;
    instruction: Instruction;
    computeUnitLimit: number;
    priorityFeeLamports?: bigint;
    setupInstructions?: readonly Instruction[];
    inputs: readonly SpentInput[];
    mergeCapacity: MergeCapacity;
  }>,
): CeilingDecision {
  const { inputs, instruction, payer } = input;
  const signers: FitSigners = {
    payer,
    ...(input.setupInstructions === undefined
      ? {}
      : { setupInstructions: input.setupInstructions }),
  };
  const budget: FitBudget = {
    computeUnitLimit: input.computeUnitLimit,
    ...(input.priorityFeeLamports === undefined
      ? {}
      : { priorityFeeLamports: input.priorityFeeLamports }),
  };
  try {
    const fit = TransactionFit.of(instruction, signers, budget);
    return Object.freeze({
      kind: "inline",
      size: Object.freeze({ bytes: fit.bytes, addresses: fit.addresses }),
    });
  } catch (cause) {
    // Only the address count leaves a route, merging first narrows the spend.
    if (!(cause instanceof RingError) || cause.code !== "RING_FIT_ADDRESSES") throw cause;
  }
  const sized = (mergedAway: ReadonlySet<Address>): TransactionSize =>
    compiled(
      {
        ...instruction,
        accounts: (instruction.accounts ?? []).filter(
          (account) => !mergedAway.has(account.address),
        ),
      },
      signers,
      budget,
    );
  const mergedAway = new Set<Address>();
  const before = sized(mergedAway);
  const chosen: MergeGroup[] = [];
  let afterMerging = before.addresses;
  for (const group of mergeGroups(inputs, input.mergeCapacity)) {
    // The merged note's own nullifier PDA replaces one of the group's.
    for (const position of group.inputs.slice(1))
      mergedAway.add((inputs[position] as SpentInput).nullifierPda);
    chosen.push(group);
    afterMerging = sized(mergedAway).addresses;
    if (afterMerging <= MAX_TRANSACTION_ADDRESSES)
      return Object.freeze({
        kind: "mergeFirst",
        groups: Object.freeze(chosen),
        addresses: afterMerging,
      });
  }
  throw new RingError("RING_ADDRESS_CEILING", {
    details: {
      compiled: before.addresses,
      limit: MAX_TRANSACTION_ADDRESSES,
      afterMerging,
      dataNotes: inputs.filter(carriesData).length,
    },
  });
}

function isTransfer(instruction: Instruction): boolean {
  const tag = instruction.data?.[0];
  return tag === RingInstructionTag.transfer || tag === RingInstructionTag.authorityTransfer;
}

function compiled(form: Instruction, signers: FitSigners, budget: FitBudget): TransactionSize {
  return transactionSize({
    ...budget,
    feePayer: signers.payer,
    ...(signers.setupInstructions === undefined
      ? {}
      : { setupInstructions: signers.setupInstructions }),
    instructions: [form],
  });
}

/** The counts read the metas with no compile, so the kit's own ceilings never name the refusal. */
function checkCounts(form: Instruction, signers: FitSigners): void {
  const setup = signers.setupInstructions ?? [];
  const signatures = transactionSignatures({
    feePayer: signers.payer,
    setupInstructions: setup,
    instructions: [form],
  });
  if (signatures > MAX_TRANSACTION_SIGNATURES)
    throw new RingError("RING_FIT_SIGNATURES", {
      // `sanitizeDetails` drops a key naming a signature.
      details: { signers: signatures, limit: MAX_TRANSACTION_SIGNATURES },
    });
  const instructions = setup.length + 1;
  if (instructions > MAX_TRANSACTION_INSTRUCTIONS)
    throw new RingError("RING_FIT_INSTRUCTIONS", {
      details: { instructions, limit: MAX_TRANSACTION_INSTRUCTIONS },
    });
}

function accept(
  input: Readonly<{
    form: Instruction;
    signers: FitSigners;
    budget: FitBudget;
    cpiBytes: number | undefined;
  }>,
): Fit {
  const { form, signers, budget, cpiBytes } = input;
  const size = compiled(form, signers, budget);
  if (size.bytes > LIMIT_BYTES)
    throw new RingError("RING_FIT_BYTES", {
      details: { bytes: size.bytes, limit: LIMIT_BYTES },
    });
  if (size.addresses > MAX_TRANSACTION_ADDRESSES)
    throw new RingError("RING_FIT_ADDRESSES", {
      details: { addresses: size.addresses, limit: MAX_TRANSACTION_ADDRESSES },
    });
  const signatures = transactionSignatures({
    feePayer: signers.payer,
    setupInstructions: signers.setupInstructions ?? [],
    instructions: [form],
  });
  return Object.freeze({
    signatures,
    bytes: size.bytes,
    addresses: size.addresses,
    ...(cpiBytes === undefined ? {} : { cpiBytes }),
    setup: setupEffect({ form, signers, budget, size, signatures }),
  });
}

function setupEffect(
  input: Readonly<{
    form: Instruction;
    signers: FitSigners;
    budget: FitBudget;
    size: TransactionSize;
    signatures: number;
  }>,
): SetupEffect {
  const { form, signers, budget, size, signatures } = input;
  const instructions = signers.setupInstructions?.length ?? 0;
  if (instructions === 0)
    return Object.freeze({ instructions: 0, signatures: 0, bytes: 0, addresses: 0 });
  const alone = compiled(form, { payer: signers.payer }, budget);
  return Object.freeze({
    instructions,
    signatures:
      signatures - transactionSignatures({ feePayer: signers.payer, instructions: [form] }),
    bytes: Math.max(size.bytes - alone.bytes, 0),
    addresses: Math.max(size.addresses - alone.addresses, 0),
  });
}

/**
 * The exact data the program forwards to SPP, undefined off the transfer tags, refused past the CPI
 * limit since the program forwards one expansion. The expansion widens outputs and messages, so a
 * frame inside one transaction can still pass it. The ring's mode decides the rail and the compact
 * frame does not name it, so the strict parser reads the frame under both rails of its tag and the
 * longer expansion counts. The zero auditor key changes no length, the expansion reads it only as a
 * view tag of fixed width.
 */
function sppCpiBytes(instruction: Instruction): number | undefined {
  if (!isTransfer(instruction)) return undefined;
  const data = Uint8Array.from(instruction.data ?? []);
  const lengths = (["confidential", "anonymous"] as const).flatMap((mode) => {
    try {
      const rail = ringRailOf(data[0] as number, mode);
      const parsed = RingTransactData.parse(data.subarray(1), rail);
      return [RingTransactData.sppDataLength(parsed, ZERO_POLICY)];
    } catch (cause) {
      if (!(cause instanceof RingError)) throw cause;
      return [];
    }
  });
  if (lengths.length === 0) throw new RingError("RING_FIT_UNPARSED_FRAME");
  const bytes = Math.max(...lengths);
  if (bytes > MAX_CPI_DATA_LEN)
    throw new RingError("RING_FIT_CPI_BYTES", {
      details: { bytes, limit: MAX_CPI_DATA_LEN },
    });
  return bytes;
}

function mergeGroups(
  inputs: readonly SpentInput[],
  capacity: MergeCapacity,
): readonly MergeGroup[] {
  const groups: { head: SpentInput; positions: number[] }[] = [];
  inputs.forEach((input, position) => {
    if (carriesData(input)) return;
    const held = groups.find((group) => mergesWith(input, group.head));
    if (held === undefined) groups.push({ head: input, positions: [position] });
    else held.positions.push(position);
  });
  const merges = groups.flatMap(({ head, positions }) => {
    const width = Math.max(
      1,
      equalBytes(head.nullifierPublicKey, ZERO_NULLIFIER_PK) ? capacity.zeroKey : capacity.keyed,
    );
    return Array.from({ length: Math.ceil(positions.length / width) }, (_, run) =>
      positions.slice(run * width, (run + 1) * width),
    )
      .filter((run) => run.length > 1)
      .map((run): MergeGroup =>
        Object.freeze({
          owner: head.owner,
          asset: head.asset,
          nullifierPublicKey: head.nullifierPublicKey,
          ...(head.ringProgramId === undefined ? {} : { ringProgramId: head.ringProgramId }),
          treeId: head.treeId,
          inputs: Object.freeze(run),
        }),
      );
  });
  return merges.sort((left, right) => right.inputs.length - left.inputs.length);
}

/** SPP merge refuses a note with a data hash. */
function carriesData(input: SpentInput): boolean {
  return input.dataHash !== undefined && !isZero(input.dataHash);
}

function mergesWith(input: SpentInput, other: SpentInput): boolean {
  return (
    input.owner.equals(other.owner) &&
    input.asset === other.asset &&
    equalBytes(input.nullifierPublicKey, other.nullifierPublicKey) &&
    input.ringProgramId === other.ringProgramId &&
    input.treeId === other.treeId
  );
}
