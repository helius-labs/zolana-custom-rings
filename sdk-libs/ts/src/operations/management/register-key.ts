import type { Address } from "@solana/kit";

import {
  type RingProver,
  type RingSealedKey,
  type RingSealedNullifierKey as SealedNullifierKey,
} from "../../rpc/ports.js";
import type { ChainReader } from "@heliuslabs/zolana/client";
import { addressBytes, equalBytes, rightAlign, indexerScalars } from "@heliuslabs/zolana/internal";
import type { Bytes31, Bytes32, Bytes33, RequestContext } from "@heliuslabs/zolana/interface";
import {
  symmetricApply,
  NullifierKey,
  X25519Keypair,
  type X25519PublicKey,
} from "@heliuslabs/zolana/keypair";
import type { ShieldedAddress } from "@heliuslabs/zolana/keypair";
import type { MemberRecord, QuadPath } from "../../protocol/membership/member-registry.js";
import { auditSharedSecret } from "../../crypto/audit/audit.js";

import { checkedCustomRingProof, type RingPolicy } from "../../protocol/codec/ring-codecs.js";
import { fetchRingPolicy } from "../../protocol/membership/config.js";
import { RingError, wrapRingError } from "../../protocol/error.js";
import { memberOfTag } from "../../protocol/membership/policy.js";
import { readOwnRecords, type RingRecordReadClient } from "../../rpc/registered-record.js";
import type { EscrowEntry } from "./record-updates.js";
import { registerKeyStatementHash } from "../../protocol/proof/statement.js";

/** Rust `NF_KEY_ENC_INFO`, separates the key stream from the audit stream. */
export const NF_KEY_ENC_INFO = new TextEncoder().encode("CRING/nfk1");

export type { SealedNullifierKey };

/** Rust `NullifierKeyEnvelope`, the sealed key and the ephemeral secret its proof witnesses. */
export interface NullifierKeyEnvelope {
  readonly ephemeralSecret: Bytes32;
  readonly sealed: SealedNullifierKey;
  readonly nullifierPublicKey: Bytes32;
}

/** The member and the auditor an escrow binds. */
export interface KeyEscrowRequest {
  /** The owner identity of the signing member. */
  readonly member: Bytes32;
  readonly auditorPublicKey: X25519PublicKey;
}

/** A sealed nullifier key and the 192-byte proof of its envelope. */
export interface ProvenEscrow {
  readonly nullifierPk: Bytes32;
  /** The tagged ephemeral key, its `u` is `ephU`. */
  readonly ephPk: Bytes33;
  readonly ephU: Bytes32;
  readonly ciphertext: Bytes32;
  readonly proof: Uint8Array;
}

/** Rust `KeyEscrowAuthority`, the holder seals and proves so the nullifier secret never leaves it. */
export interface KeyEscrowAuthority {
  nullifierPublicKey(): Bytes32;
  proveEscrow(request: KeyEscrowRequest, context?: RequestContext): Promise<ProvenEscrow>;
}

/** An in-process `KeyEscrowAuthority` over a copy of the key, `destroy` wipes the copy. */
export class NullifierKeyEscrow implements KeyEscrowAuthority {
  readonly #key: NullifierKey;
  readonly #prover: RingProver;

  constructor(nullifierKey: NullifierKey, prover: RingProver) {
    this.#key = nullifierKey.clone();
    this.#prover = prover;
  }

  nullifierPublicKey(): Bytes32 {
    return this.#key.publicKey();
  }

  async proveEscrow(request: KeyEscrowRequest, context?: RequestContext): Promise<ProvenEscrow> {
    const envelope = sealNullifierKey(this.#key, request.auditorPublicKey);
    const secret = this.#key.secretBytes();
    const nullifierSecret = rightAlign(secret);
    secret.fill(0);
    try {
      const ephU = envelope.sealed.ephemeralPublicKey.u();
      const publicInputHash = registerKeyStatementHash({
        member: request.member,
        nullifierPk: envelope.nullifierPublicKey,
        auditorPubkey: request.auditorPublicKey.toBytes(),
        ephU,
        ciphertext: envelope.sealed.ciphertext,
      });
      const proof = await this.#prover.proveRing(
        {
          kind: "registerKey",
          publicInputHash,
          member: request.member,
          nullifierSecret,
          ephSk: envelope.ephemeralSecret,
          auditorPk: request.auditorPublicKey.u(),
        },
        context,
      );
      return Object.freeze({
        nullifierPk: envelope.nullifierPublicKey,
        ephPk: envelope.sealed.ephemeralPublicKey.toBytes(),
        ephU,
        ciphertext: envelope.sealed.ciphertext,
        proof: checkedCustomRingProof(proof),
      });
    } finally {
      nullifierSecret.fill(0);
      envelope.ephemeralSecret.fill(0);
    }
  }

  destroy(): void {
    this.#key.destroy();
  }
}

/** Rust `KeyRegistration`, the writer refuses a second escrow key for one member. */
export class KeyRegistration {
  readonly #ringProgramId: Address;
  readonly #member: ShieldedAddress;
  readonly #authority: KeyEscrowAuthority;

  constructor(
    input: Readonly<{
      ringProgramId: Address;
      /** Its Solana key signs the update, its nullifier key is the one escrowed. */
      member: ShieldedAddress;
      authority: KeyEscrowAuthority;
    }>,
  ) {
    this.#ringProgramId = input.ringProgramId;
    this.#member = input.member;
    this.#authority = input.authority;
  }

  async prove(
    client: Pick<ChainReader, "getAccount">,
    context?: RequestContext,
  ): Promise<EscrowEntry> {
    try {
      const config = await fetchRingPolicy(client, this.#ringProgramId, context);
      const member = memberOfTag(addressBytes(this.#member.solanaAddress(), "member"));
      const proven = await escrowProver({
        config,
        member: this.#member,
        authority: this.#authority,
      })(member, context);
      return Object.freeze({
        kind: "escrow",
        member: indexerScalars.hash(member),
        nullifierPk: indexerScalars.hash(proven.nullifierPk),
        ephPk: indexerScalars.base64String(proven.ephPk),
        ciphertext: indexerScalars.base64String(proven.ciphertext),
        proof: indexerScalars.base64String(checkedCustomRingProof(proven.proof)),
      });
    } catch (cause) {
      throw wrapRingError("RING_BUILD_KEY_REGISTRATION", cause);
    }
  }
}

export type RingSealedKeyClient = RingRecordReadClient;

/** A member's record under the ring's newest own root, escrowing `sealed`. */
export interface RingSealedKeyEntry {
  readonly member: Bytes32;
  readonly root: Bytes32;
  readonly record: MemberRecord;
  readonly path: QuadPath;
  readonly sealed: RingSealedKey;
}

/** The key `member` escrowed, refused unless its record binds the served envelope. */
export async function fetchRingSealedKey(
  input: Readonly<{ client: RingSealedKeyClient; ringProgramId: Address; member: Bytes32 }>,
  context?: RequestContext,
): Promise<RingSealedKeyEntry> {
  const { root, reads } = await readOwnRecords(
    { client: input.client, ringProgramId: input.ringProgramId, members: [input.member] },
    context,
  );
  const [read] = reads;
  if (read === undefined)
    throw new RingError("RING_MEMBER_REGISTRY_INVALID", { details: { reason: "openings" } });
  const served = read.opening.sealedKey;
  const escrowed = served === undefined ? undefined : read.escrowed(served.nullifierPk);
  if (escrowed === undefined) throw new RingError("RING_KEY_NOT_REGISTERED");
  return Object.freeze({
    member: input.member,
    root: root.root,
    record: escrowed.record,
    path: escrowed.path,
    sealed: escrowed.sealed,
  });
}

/** The auditor's opening of an escrowed key, the opened key must be the one the record binds. */
export function openRingSealedKey(entry: RingSealedKeyEntry, auditor: X25519Keypair): NullifierKey {
  const key = openNullifierKey(entry.sealed, auditor);
  if (!equalBytes(key.publicKey(), entry.sealed.nullifierPk)) {
    key.destroy();
    throw new RingError("RING_KEY_ENVELOPE_INVALID");
  }
  return key;
}

/** `(ephemeral, auditor)` fixes the keystream, the ephemeral scalar is never taken from a caller. */
export function sealNullifierKey(
  nullifierKey: NullifierKey,
  auditorPublicKey: X25519PublicKey,
): NullifierKeyEnvelope {
  const ephemeral = X25519Keypair.generate();
  try {
    return sealNullifierKeyWith(ephemeral, nullifierKey, auditorPublicKey);
  } finally {
    ephemeral.destroy();
  }
}

/** @internal Byte zero of the plaintext is the pad the circuit pins. */
export function sealNullifierKeyWith(
  ephemeral: X25519Keypair,
  nullifierKey: NullifierKey,
  auditorPublicKey: X25519PublicKey,
): NullifierKeyEnvelope {
  const secret = nullifierKey.secretBytes();
  const plaintext = rightAlign(secret);
  let dh: Bytes32 | undefined;
  let shared: Bytes32 | undefined;
  try {
    const ephemeralPublicKey = ephemeral.publicKey();
    dh = ephemeral.ecdh(auditorPublicKey);
    shared = auditSharedSecret(dh, ephemeralPublicKey, auditorPublicKey);
    const ciphertext = symmetricApply(shared, NF_KEY_ENC_INFO, plaintext) as Bytes32;
    return Object.freeze({
      ephemeralSecret: ephemeral.secretBytes(),
      sealed: Object.freeze({ ephemeralPublicKey, ciphertext }),
      nullifierPublicKey: nullifierKey.publicKey(),
    });
  } finally {
    secret.fill(0);
    plaintext.fill(0);
    dh?.fill(0);
    shared?.fill(0);
  }
}

/** The pad alone does not authenticate the key against its registry record. */
export function openNullifierKey(sealed: SealedNullifierKey, auditor: X25519Keypair): NullifierKey {
  let dh: Bytes32 | undefined;
  let shared: Bytes32 | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    dh = auditor.ecdh(sealed.ephemeralPublicKey);
    shared = auditSharedSecret(dh, sealed.ephemeralPublicKey, auditor.publicKey());
    plaintext = symmetricApply(shared, NF_KEY_ENC_INFO, sealed.ciphertext);
    if (plaintext[0] !== 0) throw new RingError("RING_KEY_ENVELOPE_INVALID");
    return NullifierKey.fromSecret(plaintext.subarray(1) as Bytes31);
  } finally {
    dh?.fill(0);
    shared?.fill(0);
    plaintext?.fill(0);
  }
}

/** Refuses before any proof an anonymous ring or an authority holding another nullifier key. */
function escrowProver({
  config,
  member,
  authority,
}: Readonly<{
  config: RingPolicy;
  member: ShieldedAddress;
  authority: KeyEscrowAuthority;
}>): (identity: Bytes32, context: RequestContext | undefined) => Promise<ProvenEscrow> {
  if (config.mode === "anonymous") throw new RingError("RING_ANONYMOUS_REFUSED");
  const nullifierPk = authority.nullifierPublicKey();
  if (!equalBytes(nullifierPk, member.nullifierPublicKey))
    throw new RingError("RING_NULLIFIER_KEY_MISMATCH");
  return async (identity, context) => {
    const proven = await authority.proveEscrow(
      { member: identity, auditorPublicKey: config.auditorPublicKey },
      context,
    );
    if (!equalBytes(proven.nullifierPk, nullifierPk))
      throw new RingError("RING_NULLIFIER_KEY_MISMATCH");
    return proven;
  };
}
