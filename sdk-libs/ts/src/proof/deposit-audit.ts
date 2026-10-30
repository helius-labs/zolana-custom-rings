import { X25519PublicKey, X25519Keypair, symmetricApply } from "@heliuslabs/zolana/keypair";
import {
  hashBytes,
  addressBytes,
  copyBytes,
  isCanonicalField,
  bigIntBytes,
  equalBytes,
  hashChain,
  readOutputData,
  U64_MAX,
} from "@heliuslabs/zolana/internal";
import { pack33 } from "@heliuslabs/zolana/interface";
import type { Address, Bytes32, Bytes33, Bytes96 } from "@heliuslabs/zolana/interface";
import { EncryptedScheme, ownerUtxoHash } from "@heliuslabs/zolana/transaction";
import { ringIdField } from "../crypto/derivation/ring-stream.js";
import {
  decodeRingDepositOutput,
  type RingDepositOutput,
} from "../protocol/codec/ring-deposit-plaintext.js";
import {
  encodeRingDepositCapsule,
  readRingDepositCapsule,
  RING_DEPOSIT_AUDIT_SLOTS,
  RING_DEPOSIT_OPENING_LENGTH,
  RING_DEPOSIT_OPENING_OWNER_KEY_OFFSET,
  type RingDepositCapsule,
} from "../protocol/codec/deposit-capsule.js";
import { auditSharedSecret } from "../crypto/audit/audit.js";
import { RingError } from "../protocol/error.js";
import { domainField, RingDomain } from "../crypto/derivation/ring-domain.js";
import { ConfirmedDeposit } from "../protocol/transaction/origin.js";

const INFO = new TextEncoder().encode("CRING/dep1");
const OPENING_LENGTH = RING_DEPOSIT_OPENING_LENGTH;
const OWNER_KEY_OFFSET = RING_DEPOSIT_OPENING_OWNER_KEY_OFFSET;
const PAYLOAD_LENGTH = OPENING_LENGTH * RING_DEPOSIT_AUDIT_SLOTS;
const ZERO = new Uint8Array(32) as Bytes32;

/** Carries the owner commitment preimage and unchanged recipient ciphertext. */
export interface RingDepositOpening {
  readonly ownerHash: Bytes32;
  readonly blinding: Bytes32;
  /** The proof binds its Solana owner identity into `ownerHash`. */
  readonly ownerKey: Bytes32;
  readonly recipientCiphertext: Uint8Array;
}

export function sealRingDepositOpenings(
  openings: readonly RingDepositOpening[],
  auditor: X25519PublicKey,
): Readonly<{
  capsules: readonly RingDepositCapsule[];
  payloads: readonly Uint8Array[];
  ephemeralSecret: Bytes32;
}> {
  if (openings.length < 1 || openings.length > RING_DEPOSIT_AUDIT_SLOTS)
    throw new RingError("RING_BUILD_DEPOSIT", { details: { reason: "deposit count" } });
  const ephemeral = X25519Keypair.generate();
  const plaintext = new Uint8Array(PAYLOAD_LENGTH);
  let dh: Bytes32 | undefined;
  let shared: Bytes32 | undefined;
  let ciphertext: Uint8Array | undefined;
  try {
    for (const [index, opening] of openings.entries()) {
      if (!isCanonicalField(opening.ownerHash) || !isCanonicalField(opening.blinding))
        throw new RingError("RING_BUILD_DEPOSIT");
      plaintext.set(opening.ownerHash, index * OPENING_LENGTH);
      plaintext.set(opening.blinding, index * OPENING_LENGTH + 32);
      plaintext.set(
        copyBytes(opening.ownerKey, 32, "deposit owner key"),
        index * OPENING_LENGTH + OWNER_KEY_OFFSET,
      );
    }
    const ephemeralPublicKey = ephemeral.publicKey();
    dh = ephemeral.ecdh(auditor);
    shared = auditSharedSecret(dh, ephemeralPublicKey, auditor);
    ciphertext = symmetricApply(shared, INFO, plaintext);
    const encrypted = ciphertext;
    const capsules = openings.map((opening, index): RingDepositCapsule =>
      Object.freeze({
        slotIndex: index,
        ephemeralPublicKey: ephemeralPublicKey.toBytes(),
        ciphertext: encrypted.slice(
          index * OPENING_LENGTH,
          (index + 1) * OPENING_LENGTH,
        ) as Bytes96,
        recipientCiphertext: new Uint8Array(opening.recipientCiphertext),
      }),
    );
    return Object.freeze({
      capsules: Object.freeze(capsules),
      payloads: Object.freeze(capsules.map(encodeRingDepositCapsule)),
      ephemeralSecret: ephemeral.secretBytes(),
    });
  } finally {
    ephemeral.destroy();
    plaintext.fill(0);
    dh?.fill(0);
    shared?.fill(0);
    ciphertext?.fill(0);
  }
}

/** @internal Rust `deposit_output`. */
export function ringDepositOutput(
  payload: Uint8Array,
  ring: Address,
): RingDepositOutput | undefined {
  try {
    const frame = readOutputData(payload);
    if (frame.encoding !== "encrypted" || frame.scheme !== EncryptedScheme.ringDeposit)
      return undefined;
    const deposit = decodeRingDepositOutput(frame.body);
    return deposit.ringProgramId === ring ? deposit : undefined;
  } catch {
    return undefined;
  }
}

export function openRingDepositOpening(
  capsule: RingDepositCapsule,
  auditor: X25519Keypair,
  ownerCommitment: Bytes32,
  confirmed: ConfirmedDeposit,
): Readonly<{ ownerHash: Bytes32; blinding: Bytes32; ownerKey: Bytes32 }> {
  if (!ConfirmedDeposit.is(confirmed)) throw new RingError("RING_AUDIT_MESSAGE");
  const snapshot = readRingDepositCapsule(encodeRingDepositCapsule(capsule));
  if (snapshot === undefined) throw new RingError("RING_AUDIT_MESSAGE");
  capsule = snapshot;
  confirmed.authenticate(capsule, ownerCommitment);
  const ciphertext = new Uint8Array(PAYLOAD_LENGTH);
  ciphertext.set(capsule.ciphertext, capsule.slotIndex * OPENING_LENGTH);
  let dh: Bytes32 | undefined;
  let shared: Bytes32 | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    const ephemeral = X25519PublicKey.fromBytes(capsule.ephemeralPublicKey);
    dh = auditor.ecdh(ephemeral);
    shared = auditSharedSecret(dh, ephemeral, auditor.publicKey());
    plaintext = symmetricApply(shared, INFO, ciphertext);
    const start = capsule.slotIndex * OPENING_LENGTH;
    const ownerHash = plaintext.slice(start, start + 32) as Bytes32;
    const blinding = plaintext.slice(start + 32, start + OWNER_KEY_OFFSET) as Bytes32;
    const ownerKey = plaintext.slice(start + OWNER_KEY_OFFSET, start + OPENING_LENGTH) as Bytes32;
    try {
      if (
        !isCanonicalField(ownerHash) ||
        !isCanonicalField(blinding) ||
        !isCanonicalField(ownerCommitment) ||
        !equalBytes(ownerUtxoHash(ownerHash, blinding), ownerCommitment)
      )
        throw new RingError("RING_AUDIT_MESSAGE");
    } catch (cause) {
      ownerHash.fill(0);
      blinding.fill(0);
      throw cause;
    }
    return Object.freeze({ ownerHash, blinding, ownerKey });
  } finally {
    ciphertext.fill(0);
    dh?.fill(0);
    shared?.fill(0);
    plaintext?.fill(0);
  }
}

export function ringDepositContextHash(ring: Address, tree: Address, sppWire: Uint8Array): Bytes32 {
  return hashChain([
    ringIdField(ring),
    hashBytes(addressBytes(tree)) as Bytes32,
    bigIntBytes(BigInt(sppWire.length)) as Bytes32,
    hashBytes(sppWire) as Bytes32,
  ]);
}

/** Rust `DepositedAsset`, `asset` is SPP's asset field of the entry's group. */
export interface DepositedAsset {
  readonly asset: Bytes32;
  readonly amount: bigint;
}

/** Rust `DepositRegistry`. */
export interface DepositRegistry {
  readonly ownRoot: Bytes32;
  /** Absent without a curator source. */
  readonly curatorRoot?: Bytes32;
  /** Every deposited owner's record escrows the deposited nullifier key. */
  readonly keyEscrow: boolean;
  /** Its table's asset rules screen every deposited asset, absent before the first policy write. */
  readonly policyHash?: Bytes32;
}

/** Rust `DepositPublicInput`, the tagged keys as the statement packs them. */
export interface DepositStatement {
  readonly contextHash: Bytes32;
  /** Set by the program from the ring's mode. */
  readonly anonymous: boolean;
  readonly ownerUtxoHashes: readonly Bytes32[];
  readonly ciphertexts: readonly Bytes96[];
  readonly assets: readonly DepositedAsset[];
  readonly auditorPk: Bytes33;
  readonly ephPk: Bytes33;
  /** Absent off an escrow or policy ring. */
  readonly registry?: DepositRegistry;
}

/** Rust `DepositPublicInput::elements`, every slot padded to the maximum. */
export function depositStatementElements(input: DepositStatement): readonly Bytes32[] {
  const count = input.ownerUtxoHashes.length;
  if (
    count < 1 ||
    count > RING_DEPOSIT_AUDIT_SLOTS ||
    input.ciphertexts.length !== count ||
    input.assets.length !== count
  )
    throw new RingError("RING_BUILD_DEPOSIT", { details: { reason: "deposit count" } });
  if (
    !isCanonicalField(input.contextHash) ||
    typeof input.anonymous !== "boolean" ||
    !input.ownerUtxoHashes.every(isCanonicalField) ||
    !input.assets.every(
      ({ asset, amount }) => isCanonicalField(asset) && amount >= 0n && amount <= U64_MAX,
    )
  )
    throw new RingError("RING_BUILD_DEPOSIT");
  const registry = input.registry;
  return Object.freeze([
    domainField(RingDomain.depositStatement),
    input.contextHash,
    bigIntBytes(BigInt(count)) as Bytes32,
    bigIntBytes(input.anonymous ? 1n : 0n) as Bytes32,
    ...Array.from({ length: RING_DEPOSIT_AUDIT_SLOTS }, (_, slot) => {
      const owner = input.ownerUtxoHashes[slot];
      const ciphertext = input.ciphertexts[slot];
      return owner === undefined || ciphertext === undefined
        ? [ZERO, ZERO]
        : [owner, hashBytes(ciphertext) as Bytes32];
    }).flat(),
    ...pack33(input.auditorPk),
    ...pack33(input.ephPk),
    bigIntBytes(registry?.keyEscrow === true ? 1n : 0n) as Bytes32,
    registry?.ownRoot ?? ZERO,
    registry?.curatorRoot ?? ZERO,
    registry?.policyHash ?? ZERO,
    ...Array.from({ length: RING_DEPOSIT_AUDIT_SLOTS }, (_, slot) => {
      const deposited = input.assets[slot];
      return deposited === undefined
        ? [ZERO, ZERO]
        : [deposited.asset, bigIntBytes(deposited.amount) as Bytes32];
    }).flat(),
  ]);
}

/** Rust `DepositPublicInput::hash` over capsules that share one ephemeral key at their own slots. */
export function ringDepositPublicInputHash(
  input: Readonly<{
    contextHash: Bytes32;
    anonymous: boolean;
    ownerCommitments: readonly Bytes32[];
    capsules: readonly RingDepositCapsule[];
    assets: readonly DepositedAsset[];
    auditorPublicKey: X25519PublicKey;
    registry?: DepositRegistry;
  }>,
): Bytes32 {
  const [first] = input.capsules;
  if (first === undefined || input.ownerCommitments.length !== input.capsules.length)
    throw new RingError("RING_BUILD_DEPOSIT", { details: { reason: "deposit count" } });
  X25519PublicKey.fromBytes(first.ephemeralPublicKey);
  input.capsules.forEach((capsule, index) => {
    encodeRingDepositCapsule(capsule);
    if (
      capsule.slotIndex !== index ||
      !capsule.ephemeralPublicKey.every((byte, offset) => byte === first.ephemeralPublicKey[offset])
    )
      throw new RingError("RING_BUILD_DEPOSIT", { details: { reason: "deposit capsule" } });
  });
  return hashChain(
    depositStatementElements({
      contextHash: input.contextHash,
      anonymous: input.anonymous,
      ownerUtxoHashes: input.ownerCommitments,
      ciphertexts: input.capsules.map((capsule) => capsule.ciphertext),
      assets: input.assets,
      auditorPk: input.auditorPublicKey.toBytes(),
      ephPk: first.ephemeralPublicKey,
      ...(input.registry === undefined ? {} : { registry: input.registry }),
    }),
  );
}
