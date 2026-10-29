import { existsSync, readFileSync } from "node:fs";

import { AccountRole, address, getAddressDecoder, type Address, type Signature } from "@solana/kit";
import { beforeAll, describe, expect, it, vi } from "vitest";

import { type RingMemberOpenings } from "../../src/rpc/ports.js";
import {
  BN254_SCALAR_ORDER,
  hashBytes,
  treeAddress,
  bigIntToBytes,
  checkedBytes,
} from "@heliuslabs/zolana/internal";
import { initializePoseidon } from "@heliuslabs/zolana";
import {
  InstructionTag,
  DepositAsset,
  type Bytes16,
  type Bytes32,
  type Bytes33,
  type Bytes96,
} from "@heliuslabs/zolana/interface";
import {
  ownerHash,
  ShieldedKeypair,
  ViewingKey,
  X25519Keypair,
  X25519PublicKey,
} from "@heliuslabs/zolana/keypair";
import { SOL_MINT, ownerUtxoHash } from "@heliuslabs/zolana/transaction";
import { LocalRingKeys } from "../../src/state/ring-keys.js";
import type { RingProofRequest } from "../../src/rpc/prover/ring.js";
import { ringConfigPda, ringMemberRegistryPda } from "../../src/protocol/pda/index.js";
import { depositBlinding } from "../../src/crypto/derivation/ring-domain.js";
import {
  RING_COSIGN_DEPOSITS,
  RING_COSIGN_TRANSFERS,
  type RingCoSigner,
  type RingMode,
} from "../../src/protocol/codec/ring-codecs.js";
import {
  PreparedRingDeposit,
  buildRingDepositTransaction,
  type RingDepositClient,
  type RingDepositParams,
} from "../../src/operations/payments/deposit.js";
import {
  openRingDepositOpening,
  ringDepositContextHash,
  ringDepositPublicInputHash,
  sealRingDepositOpenings,
} from "../../src/proof/deposit-audit.js";
import {
  encodeRingDepositCapsule,
  readRingDepositCapsule,
} from "../../src/protocol/codec/deposit-capsule.js";
import { ringDepositInstruction } from "../../src/protocol/transaction/deposit-instruction.js";
import { decryptRingDepositUtxo } from "../../src/protocol/transaction/deposit-payload.js";
import { encodeRingDepositPlaintext } from "../../src/protocol/codec/ring-deposit-plaintext.js";
import { escrowKeyHash } from "../../src/protocol/membership/member-opening.js";
import { ConfirmedDeposit } from "../../src/protocol/transaction/origin.js";
import { ListId, recordBit } from "../../src/protocol/membership/policy.js";
import { BLOCKHASH } from "../../../../zolana/sdk-libs/ts/test/helpers/clients.js";
import { confirmedDepositTransaction } from "../helpers/confirmed-deposits.js";
import { recordTree, type FixtureRecord } from "../helpers/member-registry.js";
import {
  memberRegistryData,
  ownedAccount,
  ringProgramConfigData,
} from "../helpers/ring-accounts.js";
import { type RingKeys } from "../../src/state/ring-keys.js";
import {
  TransferTagging,
  ViewingHistory,
  type FirstContact,
} from "../../src/state/viewing-history.js";
import { RingAddress } from "../../src/crypto/keys/ring-address.js";

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const TREE = treeAddress(0);
const PAYER = address("4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T");
const CONTEXT = Object.freeze({ slot: 1n, blockTime: 1n });
function field(value: bigint): Bytes32 {
  return bigIntToBytes(value) as Bytes32;
}
function hex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}
beforeAll(initializePoseidon);

describe("deposit disclosure", () => {
  it("pins the shared Rust and Go encryption and statement vector", () => {
    const auditor = X25519Keypair.fromBytes(new Uint8Array(32).fill(0x11) as Bytes32);
    const generate = vi
      .spyOn(X25519Keypair, "generate")
      .mockImplementation(() => X25519Keypair.fromBytes(new Uint8Array(32).fill(0x22) as Bytes32));
    const sealed = sealRingDepositOpenings(
      [
        { ownerHash: field(1n), blinding: field(3n), recipientCiphertext: Uint8Array.of(1) },
        { ownerHash: field(2n), blinding: field(4n), recipientCiphertext: Uint8Array.of(2) },
      ],
      auditor.publicKey(),
    );
    try {
      const contextHash = ringDepositContextHash(
        getAddressDecoder().decode(new Uint8Array(32).fill(0x33)),
        getAddressDecoder().decode(new Uint8Array(32).fill(0x44)),
        Uint8Array.of(18, 1, 0, 2),
      );
      expect(hex(contextHash)).toBe(
        "2cc6b9a5a2cb550702b5387ade744abee5e6eeb7c266415e59502e6f8acce56b",
      );
      expect(sealed.capsules.map((capsule) => hex(capsule.ciphertext))).toEqual([
        "006d5d4d188464de0e852c806b11ef3850cd683b977fea9bd1b9278b6461669f631350fa47a91f10cceb37738a4fefe7f88ded2f36b08fa08cb0ebba0268414424ab3ee9887da5fa32d2074fbd7155bc72723a28dacb3fd92f045649bba3cdf6",
        "588ca73e11d9094a68cc5e7c26aadac08f1bc0f41c3580bf9ddc70518b26a826aaeab0368c456598c7641706ce6de7dcdbafa8c64f3eba9526b5012da75c1a4c4fb93b88049bc84e8589460c06610c931447f57d2d4a9955f6ec638727886729",
      ]);
      const hash = ringDepositPublicInputHash({
        contextHash,
        anonymous: false,
        ownerCommitments: [
          ownerUtxoHash(field(1n), field(3n)),
          ownerUtxoHash(field(2n), field(4n)),
        ],
        capsules: sealed.capsules,
        assets: [
          { asset: field(5n), amount: 7n },
          { asset: field(6n), amount: 8n },
        ],
        auditorPublicKey: auditor.publicKey(),
      });
      expect(hex(hash)).toBe("10e19c9868fa518ed2799983f62d30b1b6463c57bd721b93e0c60eec1f9e17e4");
    } finally {
      generate.mockRestore();
      sealed.ephemeralSecret.fill(0);
      auditor.destroy();
    }
  });

  const golden = new URL(
    "../../../../prover/ring/testdata/deposit/custom-ring-deposit-1.json",
    import.meta.url,
  );
  // The Go ring prover goldens live outside the repository.
  it.runIf(existsSync(golden))(
    "reproduces the statement of the Go deposit golden from its proof inputs",
    () => {
      const fixture = JSON.parse(readFileSync(golden, "utf8")) as Record<string, unknown>;
      const word = (value: unknown): Bytes32 => {
        if (typeof value !== "string") throw new Error("golden field");
        return Uint8Array.from(Buffer.from(value.slice(2).padStart(64, "0"), "hex")) as Bytes32;
      };
      const words = (value: unknown): Bytes32[] => {
        if (!Array.isArray(value)) throw new Error("golden list");
        return value.map(word);
      };
      const count = Number(fixture["count"]);
      const amounts = (fixture["amounts"] as string[]).map((value) => BigInt(value));
      const ownerPkHashes = words(fixture["ownerPkHashes"]);
      const nullifierPks = words(fixture["nullifierPks"]);
      const secrets = words(fixture["blindingSecrets"]);
      const openings = Array.from({ length: count }, (_, slot) => {
        const owner = ownerHash(ownerPkHashes[slot] ?? field(0n), nullifierPks[slot] ?? field(0n));
        const blinding = depositBlinding(secrets[slot] ?? field(0n));
        return {
          ownerHash: owner as Bytes32,
          blinding,
          recipientCiphertext: new Uint8Array(),
        };
      });
      const ephemeral = word(fixture["ephSk"]);
      const generate = vi
        .spyOn(X25519Keypair, "generate")
        .mockImplementation(() => X25519Keypair.fromBytes(ephemeral));
      const auditor = X25519PublicKey.fromBytes(
        Uint8Array.of(4, ...word(fixture["auditorPk"])) as Bytes33,
      );
      const sealed = sealRingDepositOpenings(openings, auditor);
      try {
        const hash = ringDepositPublicInputHash({
          contextHash: word(fixture["contextHash"]),
          anonymous: fixture["anonymous"] === true,
          ownerCommitments: openings.map((opening) =>
            ownerUtxoHash(opening.ownerHash, opening.blinding),
          ),
          capsules: sealed.capsules,
          assets: words(fixture["assets"])
            .slice(0, count)
            .map((asset, slot) => ({ asset, amount: amounts[slot] ?? 0n })),
          auditorPublicKey: auditor,
          registry: {
            ownRoot: word(fixture["memberRegistryRoot"]),
            keyEscrow: fixture["keyEscrow"] === true,
            policyHash: word(fixture["policyHash"]),
          },
        });
        expect(hex(hash)).toBe(String(fixture["publicInputHash"]).slice(2));
      } finally {
        generate.mockRestore();
        sealed.ephemeralSecret.fill(0);
      }
    },
  );

  it("opens every slot of one shared stream and preserves recipient ciphertext", () => {
    const auditor = X25519Keypair.generate();
    // Odd slots disclose an owner key like an anonymous ring.
    const openings = Array.from({ length: 8 }, (_, index) => ({
      ownerHash: field(BigInt(index + 1)),
      blinding: field(BigInt(index + 11)),
      ...(index % 2 === 0 ? {} : { ownerKey: new Uint8Array(32).fill(index) as Bytes32 }),
      recipientCiphertext: Uint8Array.of(index, 9),
    }));
    const sealed = sealRingDepositOpenings(openings, auditor.publicKey());
    const signature = "1".repeat(87) as Signature;
    const confirmed = ConfirmedDeposit.fromTransaction(
      confirmedDepositTransaction(
        RING,
        signature,
        sealed.capsules,
        openings.map((opening) => ownerUtxoHash(opening.ownerHash, opening.blinding)),
      ),
      signature,
      0,
      RING,
    );
    try {
      for (const [index, encoded] of sealed.payloads.entries()) {
        const capsule = readRingDepositCapsule(encoded);
        const opening = openings[index];
        const binding = confirmed[index];
        if (capsule === undefined || opening === undefined || binding === undefined)
          throw new Error("missing slot");
        expect(capsule.slotIndex).toBe(index);
        expect(capsule.ephemeralPublicKey).toEqual(sealed.capsules[0]?.ephemeralPublicKey);
        expect(capsule.recipientCiphertext).toEqual(opening.recipientCiphertext);
        const opened = openRingDepositOpening(
          capsule,
          auditor,
          ownerUtxoHash(opening.ownerHash, opening.blinding),
          binding,
        );
        expect(opened.ownerHash).toEqual(opening.ownerHash);
        expect(opened.blinding).toEqual(opening.blinding);
        expect(opened.ownerKey).toEqual(opening.ownerKey);
        expect(() => openRingDepositOpening(capsule, auditor, field(0n), binding)).toThrow(
          expect.objectContaining({ code: "RING_AUDIT_MESSAGE" }),
        );
      }
      const first = sealed.capsules[0];
      if (first === undefined) throw new Error("missing capsule");
      expect(() =>
        readRingDepositCapsule(sealed.payloads[0]?.slice(0, 137) ?? new Uint8Array()),
      ).toThrow(
        expect.objectContaining({ code: "INTERFACE_CODEC", details: { field: "deposit capsule" } }),
      );
      expect(() => encodeRingDepositCapsule({ ...first, slotIndex: 8 })).toThrow(
        expect.objectContaining({ code: "INTERFACE_CODEC", details: { field: "deposit slot" } }),
      );
      expect(readRingDepositCapsule(Uint8Array.of(1, 2, 3))).toBeUndefined();
    } finally {
      sealed.ephemeralSecret.fill(0);
      auditor.destroy();
    }
  });

  it("binds the SPP wire, both addresses, the anonymous flag, the commitments and the ciphertext", () => {
    const auditor = X25519Keypair.generate();
    const sealed = sealRingDepositOpenings(
      [{ ownerHash: field(1n), blinding: field(2n), recipientCiphertext: Uint8Array.of(3) }],
      auditor.publicKey(),
    );
    try {
      const contextHash = ringDepositContextHash(RING, TREE, Uint8Array.of(18, 1));
      expect(ringDepositContextHash(RING, TREE, Uint8Array.of(18, 2))).not.toEqual(contextHash);
      expect(ringDepositContextHash(TREE, RING, Uint8Array.of(18, 1))).not.toEqual(contextHash);
      const input = {
        contextHash,
        anonymous: false,
        ownerCommitments: [ownerUtxoHash(field(1n), field(2n))],
        capsules: sealed.capsules,
        assets: [{ asset: field(4n), amount: 5n }],
        auditorPublicKey: auditor.publicKey(),
      };
      const hash = ringDepositPublicInputHash(input);
      expect(ringDepositPublicInputHash({ ...input, anonymous: true })).not.toEqual(hash);
      expect(ringDepositPublicInputHash({ ...input, ownerCommitments: [field(3n)] })).not.toEqual(
        hash,
      );
      expect(
        ringDepositPublicInputHash({ ...input, assets: [{ asset: field(4n), amount: 6n }] }),
      ).not.toEqual(hash);
      expect(
        ringDepositPublicInputHash({
          ...input,
          registry: { ownRoot: field(0n), keyEscrow: false, policyHash: field(9n) },
        }),
      ).not.toEqual(hash);
      expect(() =>
        ringDepositPublicInputHash({ ...input, contextHash: field(BN254_SCALAR_ORDER) }),
      ).toThrow(expect.objectContaining({ code: "RING_BUILD_DEPOSIT" }));
      const capsule = sealed.capsules[0];
      if (capsule === undefined) throw new Error("missing capsule");
      capsule.ciphertext[0] = (capsule.ciphertext[0] ?? 0) ^ 1;
      expect(ringDepositPublicInputHash(input)).not.toEqual(hash);
    } finally {
      sealed.ephemeralSecret.fill(0);
      auditor.destroy();
    }
  });

  it("unwraps the recipient ciphertext behind the auditor capsule", () => {
    const auditor = X25519Keypair.generate();
    const envelope = ViewingKey.generate();
    const recipient = ShieldedKeypair.generate();
    const blinding = field(15n);
    const salt = new Uint8Array(16) as Bytes16;
    const ciphertext = envelope.encryptRingDeposit(
      recipient.viewingPublicKey(),
      encodeRingDepositPlaintext({ blinding, ringData: Uint8Array.of(9) }),
      salt,
    );
    const sealed = sealRingDepositOpenings(
      [
        {
          ownerHash: recipient.shieldedAddress().ownerHash(),
          blinding,
          recipientCiphertext: ciphertext,
        },
      ],
      auditor.publicKey(),
    );
    try {
      const output = {
        ownerUtxoHash: ownerUtxoHash(recipient.shieldedAddress().ownerHash(), blinding),
        asset: SOL_MINT,
        amount: 7n,
        ringProgramId: RING,
        ringDataHash: field(0n),
        encrypted: { txViewingPublicKey: envelope.publicKey().toBytes(), salt, ciphertext },
      };
      const bare = decryptRingDepositUtxo(output, recipient, recipient.signingPublicKey());
      const capsule = sealed.payloads[0];
      if (capsule === undefined) throw new Error("missing capsule");
      const audited = decryptRingDepositUtxo(
        { ...output, encrypted: { ...output.encrypted, ciphertext: capsule } },
        recipient,
        recipient.signingPublicKey(),
      );
      expect(audited.blinding).toEqual(bare.blinding);
      expect(audited.data).toEqual(bare.data);
    } finally {
      sealed.ephemeralSecret.fill(0);
      envelope.destroy();
      auditor.destroy();
      recipient.destroy();
    }
  });
});

describe("audited deposit instruction", () => {
  it("prefixes the proof and the root slot and keeps the SPP deposit bytes and accounts", async () => {
    const auditor = X25519Keypair.generate();
    const sealed = sealRingDepositOpenings(
      Array.from({ length: 8 }, () => ({
        ownerHash: field(1n),
        blinding: field(2n),
        recipientCiphertext: Uint8Array.of(3),
      })),
      auditor.publicKey(),
    );
    try {
      const deposits = sealed.payloads.map((ciphertext) => ({
        asset: DepositAsset.sol(),
        viewTag: field(1n),
        ownerUtxoHash: ownerUtxoHash(field(1n), field(2n)),
        amount: 1n,
        ringDataHash: field(0n),
        encrypted: {
          txViewingPublicKey: auditor.publicKey().toBytes(),
          salt: new Uint8Array(16) as Bytes16,
          ciphertext,
        },
      }));
      const input = { ringProgramId: RING, tree: TREE, depositor: PAYER, deposits };
      const proof = new Uint8Array(192).fill(7);
      const plain = await ringDepositInstruction({ ...input, proof });
      const escrowed = await ringDepositInstruction({
        ...input,
        proof,
        registryRootIndex: 5,
        cosigner: RING,
      });
      const [config] = await ringConfigPda(RING);
      const [registry] = await ringMemberRegistryPda(RING);
      expect(plain.data?.[0]).toBe(31);
      expect(plain.data?.slice(1, 193)).toEqual(proof);
      expect(plain.data?.[193]).toBe(0);
      expect(plain.data?.[194]).toBe(InstructionTag.ringDeposit);
      expect(escrowed.data?.[193]).toBe(5);
      expect(escrowed.data?.slice(194)).toEqual(plain.data?.slice(194));
      expect(plain.accounts?.slice(0, 1)).toEqual([
        { address: config, role: AccountRole.READONLY },
      ]);
      expect(escrowed.accounts?.slice(0, 3)).toEqual([
        { address: config, role: AccountRole.READONLY },
        { address: registry, role: AccountRole.READONLY },
        { address: RING, role: AccountRole.READONLY_SIGNER },
      ]);
      expect(escrowed.accounts?.slice(3)).toEqual(plain.accounts?.slice(1));
      await expect(
        ringDepositInstruction({ ...input, proof, deposits: [...deposits, deposits[0]!] }),
      ).rejects.toMatchObject({ code: "INTERFACE_CODEC", details: { field: "deposit count" } });
      await expect(
        ringDepositInstruction({ ...input, proof: new Uint8Array(191) }),
      ).rejects.toMatchObject({
        code: "INTERFACE_INVALID_LENGTH",
        details: { name: "deposit proof", expected: 192, actual: 191 },
      });
      await expect(
        ringDepositInstruction({ ...input, proof, deposits: [...deposits].reverse() }),
      ).rejects.toMatchObject({ code: "INTERFACE_CODEC", details: { field: "deposit capsule" } });
    } finally {
      sealed.ephemeralSecret.fill(0);
      auditor.destroy();
    }
  });
});

describe("ring deposit builder", () => {
  const auditor = X25519Keypair.generate();
  const SEALED_CIPHERTEXT = field(0x5ea1n);

  /** A ring of `mode` with the registry `members`. */
  async function fixture(
    input: Readonly<{
      mode: RingMode;
      members?: readonly FixtureRecord[];
      coSigner?: RingCoSigner;
    }>,
  ) {
    const records = recordTree(input.members ?? []);
    const [config, configBump] = await ringConfigPda(RING);
    const [registry, registryBump] = await ringMemberRegistryPda(RING);
    const requests: RingProofRequest[] = [];
    const proveRing = vi.fn(async (request: RingProofRequest) => {
      requests.push(request);
      return new Uint8Array(192).fill(9);
    });
    const client: RingDepositClient = {
      tree: TREE,
      treeId: 0,
      getLatestBlockhash: async () => BLOCKHASH,
      getAccount: async (account: Address) => {
        if (account === config)
          return ownedAccount(
            RING,
            ringProgramConfigData({
              authority: RING,
              auditorPublicKey: auditor.publicKey().toBytes(),
              bump: configBump,
              hasPolicy: false,
              mode: input.mode,
              ...(input.coSigner === undefined ? {} : { coSigner: input.coSigner }),
            }),
          );
        if (account === registry)
          return ownedAccount(
            RING,
            memberRegistryData({
              bump: registryBump,
              history: [{ root: records.root, applied: 0n, slot: 0n }],
              nextIndex: records.nextIndex,
            }),
          );
        return undefined;
      },
      getRingMemberOpenings: async (request) =>
        ({
          context: CONTEXT,
          root: { root: records.root, rootIndex: 0, applied: 0n, nextIndex: records.nextIndex },
          openings: request.members.map((member) => records.opening(member)),
        }) satisfies RingMemberOpenings,
      proveRing,
    };
    return { client, requests, proveRing };
  }

  function params(
    client: RingDepositClient,
    recipient: RingDepositParams["recipient"],
    overrides: Partial<RingDepositParams> = {},
  ): RingDepositParams {
    return { client, ringProgramId: RING, feePayer: PAYER, recipient, amount: 5n, ...overrides };
  }

  /** The member's record escrowing `nullifierPk` under the sealed ciphertext. */
  function escrowedMember(member: ShieldedKeypair, nullifierPk = member.nullifierPublicKey()) {
    const memberKey = member.signingPublicKey().ownerProofInputHash();
    return {
      member: memberKey,
      lists: recordBit(ListId.escrow),
      escrowKey: escrowKeyHash({ nullifierPk, ciphertext: SEALED_CIPHERTEXT }),
      sealed: {
        owner: member.shieldedAddress().solanaAddress(),
        nullifierPk,
        ephemeralPublicKey: auditor.publicKey(),
        ciphertext: SEALED_CIPHERTEXT,
      },
    } satisfies FixtureRecord;
  }

  /** A holder answering only what an anonymous deposit asks, every other call fails. */
  function remoteKeys(local: LocalRingKeys): RingKeys {
    const refused = (): never => {
      throw new Error("the deposit asked the key holder for more than its tags");
    };
    return {
      address: () => local.address(),
      viewTags: (requests) => local.viewTags(requests),
      sharedViewTags: (requests) => local.sharedViewTags(requests),
      viewingPublicKeys: refused,
      decrypt: refused,
      derive: refused,
      transactionKeys: refused,
      ringDeliverySecrets: refused,
    };
  }

  /** A history whose current key took `count` sender tags. */
  async function advancedHistory(keys: LocalRingKeys, count: number): Promise<ViewingHistory> {
    let history = ViewingHistory.create(keys.address().viewingPublicKey, 0n);
    for (let taken = 0; taken < count; taken++) history = (await history.senderTag(keys)).history;
    return history;
  }

  /** Whether the proven deposit's SPP data carries `tag`. */
  async function publishes(
    prepared: PreparedRingDeposit,
    client: RingDepositClient,
    tag: Uint8Array,
  ): Promise<boolean> {
    const proven = await prepared.prove(client);
    return hex(Uint8Array.from(proven.instruction.data ?? [])).includes(hex(tag));
  }

  it("binds a registry ring deposit to the recipient's escrowed key under the newest root", async () => {
    const recipient = ShieldedKeypair.generate();
    const { client, requests } = await fixture({
      mode: "confidentialEscrow",
      members: [escrowedMember(recipient)],
    });
    const prepared = await PreparedRingDeposit.prepare(
      params(client, { kind: "confidential", address: recipient.shieldedAddress() }),
    );
    try {
      const proven = await prepared.prove(client);
      const [request] = requests;
      if (request?.kind !== "deposit") throw new Error("expected one deposit request");
      expect(request.keyEscrow).toBe(true);
      expect(request.anonymous).toBe(false);
      expect(request.ownerKeys).toBeUndefined();
      expect(request.ctHashes[0]).toEqual(hashBytes(SEALED_CIPHERTEXT));
      expect(request.members[0]?.record.escrowKey).toEqual(
        escrowKeyHash({
          nullifierPk: recipient.nullifierPublicKey(),
          ciphertext: SEALED_CIPHERTEXT,
        }),
      );
      expect(request.memberRegistryRoot).toEqual(recordTree([escrowedMember(recipient)]).root);
      expect(request.blindingSecrets).toHaveLength(1);
      expect(proven.roots).toEqual([
        { ringProgramId: RING, rootIndex: 0, root: recordTree([escrowedMember(recipient)]).root },
      ]);
      const data = proven.instruction.data ?? new Uint8Array();
      expect(data[193]).toBe(0);
      const [registry] = await ringMemberRegistryPda(RING);
      expect(proven.instruction.accounts?.[1]).toEqual({
        address: registry,
        role: AccountRole.READONLY,
      });
      // The recipient opens its note from the ciphertext behind the capsule.
      const spp = data.slice(194);
      expect(spp[0]).toBe(InstructionTag.ringDeposit);
      expect(prepared.utxo.blinding).toEqual(
        depositBlinding(request.blindingSecrets[0] ?? field(0n)),
      );
      expect(prepared.utxo.ringProgramId).toBe(RING);
    } finally {
      prepared.destroy();
      recipient.destroy();
    }
    expect(requests[0]?.kind === "deposit" && requests[0].blindingSecrets[0]).toEqual(field(0n));
  });

  it("refuses a recipient whose record escrows another key before any proof", async () => {
    const recipient = ShieldedKeypair.generate();
    const { client, proveRing } = await fixture({
      mode: "confidentialEscrow",
      members: [escrowedMember(recipient, field(77n))],
    });
    const prepared = await PreparedRingDeposit.prepare(
      params(client, { kind: "confidential", address: recipient.shieldedAddress() }),
    );
    try {
      await expect(prepared.prove(client)).rejects.toMatchObject({
        code: "RING_BUILD_DEPOSIT",
        causeCode: "RING_UNREGISTERED_OUTPUT_KEY",
      });
      expect(proveRing).not.toHaveBeenCalled();
    } finally {
      prepared.destroy();
      recipient.destroy();
    }
  });

  it("funds the hidden owner's next sender tag through a remote key holder", async () => {
    const owner = ShieldedKeypair.generate();
    const local = LocalRingKeys.fromKeypair(owner);
    const viewing = owner.viewingKey();
    const tags = [0n, 1n, 2n].map((count) => viewing.senderViewTag(count));
    viewing.destroy();
    const { client, requests } = await fixture({ mode: "anonymous" });
    const history = await advancedHistory(local, 2);
    const prepared = await PreparedRingDeposit.prepare(
      params(client, { kind: "anonymous", keys: remoteKeys(local), history }),
    );
    try {
      const proven = await prepared.prove(client);
      const [request] = requests;
      if (request?.kind !== "deposit") throw new Error("expected one deposit request");
      expect(request.anonymous).toBe(true);
      expect(request.keyEscrow).toBe(false);
      expect(request.ownerKeys?.[0]).toEqual(owner.signingPublicKey().ed25519());
      expect(request.members.every((member) => member === undefined)).toBe(true);
      expect(proven.roots).toBeUndefined();
      const [registry] = await ringMemberRegistryPda(RING);
      expect(proven.instruction.accounts?.map((account) => account.address)).not.toContain(
        registry,
      );
      const spp = (proven.instruction.data ?? new Uint8Array()).slice(194);
      const [lowest, next, stored] = tags.map(hex);
      expect(hex(spp)).toContain(stored);
      expect(hex(spp)).not.toContain(lowest);
      expect(hex(spp)).not.toContain(next);
      expect(prepared.utxo.owner.equals(owner.signingPublicKey())).toBe(true);
      expect(prepared.viewingHistory?.current().txCount).toBe(3n);
    } finally {
      prepared.destroy();
      local.destroy();
      owner.destroy();
    }
  });

  it("takes the next sender tag from the stored history and refuses a plain anonymous build", async () => {
    const owner = ShieldedKeypair.generate();
    const local = LocalRingKeys.fromKeypair(owner);
    const viewing = owner.viewingKey();
    const first = viewing.senderViewTag(0n);
    const second = viewing.senderViewTag(1n);
    viewing.destroy();
    const { client, proveRing } = await fixture({ mode: "anonymous" });
    const deposit = (history: ViewingHistory) =>
      params(client, { kind: "anonymous", keys: local, history });
    const prepared: PreparedRingDeposit[] = [];
    try {
      const history = ViewingHistory.create(owner.shieldedAddress().viewingPublicKey, 0n);
      await expect(buildRingDepositTransaction(deposit(history))).rejects.toMatchObject({
        code: "RING_BUILD_DEPOSIT",
        causeCode: "RING_ANONYMOUS_SUBMISSION_REQUIRED",
        cause: { details: { use: "PreparedRingDeposit" } },
      });
      expect(proveRing).not.toHaveBeenCalled();
      const initial = await PreparedRingDeposit.prepare(deposit(history));
      prepared.push(initial);
      expect(await publishes(initial, client, first)).toBe(true);
      const stored = initial.viewingHistory;
      if (stored === undefined) throw new Error("no history");
      const next = await PreparedRingDeposit.prepare(deposit(stored));
      prepared.push(next);
      expect(await publishes(next, client, second)).toBe(true);
      expect(await publishes(next, client, first)).toBe(false);
    } finally {
      for (const held of prepared) held.destroy();
      local.destroy();
      owner.destroy();
    }
  });

  it("takes a first contact tag for another member until a transfer pairs", async () => {
    const member = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const local = LocalRingKeys.fromKeypair(member);
    const { client } = await fixture({ mode: "anonymous" });
    const to = new RingAddress({ recipient: recipient.shieldedAddress(), ringProgramId: RING });
    const recipientKey = recipient.shieldedAddress().viewingPublicKey;
    const request = recipient.viewingKey().recipientRequestViewTag(0n);
    const history = ViewingHistory.create(member.shieldedAddress().viewingPublicKey, 0n);
    const paid = (held: ViewingHistory, firstContact: FirstContact) =>
      PreparedRingDeposit.prepare(
        params(client, {
          kind: "anonymousPayment",
          keys: remoteKeys(local),
          history: held,
          to,
          firstContact,
        }),
      );
    const prepared: PreparedRingDeposit[] = [];
    try {
      const bootstrap = await paid(history, { kind: "bootstrap" });
      prepared.push(bootstrap);
      expect(await publishes(bootstrap, client, recipientKey.u())).toBe(true);
      const requested = await paid(history, { kind: "request", tag: request });
      prepared.push(requested);
      expect(await publishes(requested, client, request)).toBe(true);
      const unpaired = bootstrap.viewingHistory;
      if (unpaired === undefined) throw new Error("no history");
      // A deposit body names no sender, its recipient never learns the pair.
      expect(unpaired.current().txCount).toBe(0n);
      expect(unpaired.current().knownRecipients()).toEqual([]);
      const paired = (
        await new TransferTagging({
          keys: local,
          history: unpaired,
          recipients: [{ viewingPublicKey: recipientKey, firstContact: { kind: "bootstrap" } }],
        }).plan()
      ).history;
      const shared = await paid(paired, { kind: "request", tag: request });
      prepared.push(shared);
      const viewing = member.viewingKey();
      const sharedTag = viewing.sendSharedViewTags(recipientKey).tag(0n);
      expect(await publishes(shared, client, sharedTag)).toBe(true);
      viewing.destroy();
      expect(
        shared.viewingHistory
          ?.current()
          .counter({ kind: "toRecipient", counterparty: recipientKey })?.next,
      ).toBe(1n);
    } finally {
      for (const deposit of prepared) deposit.destroy();
      local.destroy();
      member.destroy();
      recipient.destroy();
    }
  });

  it("refuses an address of another ring before any proof", async () => {
    const owner = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const local = LocalRingKeys.fromKeypair(owner);
    const { client, proveRing } = await fixture({ mode: "anonymous" });
    const other = address("SysvarRent111111111111111111111111111111111");
    try {
      await expect(
        PreparedRingDeposit.prepare(
          params(client, {
            kind: "anonymousPayment",
            keys: remoteKeys(local),
            history: ViewingHistory.create(owner.shieldedAddress().viewingPublicKey, 0n),
            to: new RingAddress({ recipient: recipient.shieldedAddress(), ringProgramId: other }),
            firstContact: { kind: "bootstrap" },
          }),
        ),
      ).rejects.toMatchObject({ code: "RING_BUILD_DEPOSIT", causeCode: "RING_FOREIGN_RING" });
      expect(proveRing).not.toHaveBeenCalled();
    } finally {
      local.destroy();
      owner.destroy();
      recipient.destroy();
    }
  });

  it("refuses a public signer that names the hidden owner", async () => {
    const owner = ShieldedKeypair.generate();
    const local = LocalRingKeys.fromKeypair(owner);
    const { client, proveRing } = await fixture({ mode: "anonymous" });
    try {
      await expect(
        PreparedRingDeposit.prepare(
          params(
            client,
            {
              kind: "anonymous",
              keys: remoteKeys(local),
              history: ViewingHistory.create(owner.shieldedAddress().viewingPublicKey, 0n),
            },
            { feePayer: owner.shieldedAddress().solanaAddress() },
          ),
        ),
      ).rejects.toMatchObject({
        code: "RING_BUILD_DEPOSIT",
        causeCode: "RING_ANONYMOUS_SIGNER_LINKS_OWNER",
      });
      expect(proveRing).not.toHaveBeenCalled();
    } finally {
      local.destroy();
      owner.destroy();
    }
  });

  it("refuses a recipient the ring mode does not admit", async () => {
    const owner = ShieldedKeypair.generate();
    const local = LocalRingKeys.fromKeypair(owner);
    try {
      const anonymous = await fixture({ mode: "anonymous" });
      await expect(
        PreparedRingDeposit.prepare(
          params(anonymous.client, { kind: "confidential", address: owner.shieldedAddress() }),
        ),
      ).rejects.toMatchObject({ causeCode: "RING_ANONYMOUS_REFUSED" });
      const registry = await fixture({ mode: "confidentialEscrow" });
      await expect(
        PreparedRingDeposit.prepare(
          params(registry.client, {
            kind: "anonymous",
            keys: remoteKeys(local),
            history: ViewingHistory.create(owner.shieldedAddress().viewingPublicKey, 0n),
          }),
        ),
      ).rejects.toMatchObject({ causeCode: "RING_NOT_ANONYMOUS" });
    } finally {
      local.destroy();
      owner.destroy();
    }
  });

  it("carries the co-signer only when its scope covers deposits", async () => {
    const recipient = ShieldedKeypair.generate();
    const cosigner = getAddressDecoder().decode(new Uint8Array(32).fill(0x55));
    try {
      const covered = await fixture({
        mode: "confidential",
        coSigner: { signer: cosigner, scope: RING_COSIGN_DEPOSITS },
      });
      const deposit = { kind: "confidential", address: recipient.shieldedAddress() } as const;
      await expect(
        PreparedRingDeposit.prepare(params(covered.client, deposit)),
      ).rejects.toMatchObject({ causeCode: "RING_COSIGNER_REQUIRED" });
      const signed = await PreparedRingDeposit.prepare(
        params(covered.client, deposit, { cosigner }),
      );
      const outside = await fixture({
        mode: "confidential",
        coSigner: { signer: cosigner, scope: RING_COSIGN_TRANSFERS },
      });
      const unsigned = await PreparedRingDeposit.prepare(
        params(outside.client, deposit, { cosigner }),
      );
      try {
        const withCoSigner = await signed.prove(covered.client);
        const withoutCoSigner = await unsigned.prove(outside.client);
        expect(withCoSigner.instruction.accounts?.[1]).toEqual({
          address: cosigner,
          role: AccountRole.READONLY_SIGNER,
        });
        expect(
          withoutCoSigner.instruction.accounts?.map((account) => account.address),
        ).not.toContain(cosigner);
      } finally {
        signed.destroy();
        unsigned.destroy();
      }
    } finally {
      recipient.destroy();
    }
  });
});

describe("confirmed deposit attribution", () => {
  it("opens an unknown owner only with its confirmed capsule and rejects altered or swapped bytes", () => {
    const auditor = X25519Keypair.generate();
    const signature = "1".repeat(87) as Signature;
    const ownerKey = new Uint8Array(32).fill(7) as Bytes32;
    const owners = [ownerUtxoHash(field(1n), field(2n)), ownerUtxoHash(field(3n), field(4n))];
    const sealed = sealRingDepositOpenings(
      [
        {
          ownerHash: field(1n),
          blinding: field(2n),
          ownerKey,
          recipientCiphertext: Uint8Array.of(9),
        },
        {
          ownerHash: field(3n),
          blinding: field(4n),
          recipientCiphertext: Uint8Array.of(8),
        },
      ],
      auditor.publicKey(),
    );
    try {
      const transaction = confirmedDepositTransaction(RING, signature, sealed.capsules, owners);
      const bindings = ConfirmedDeposit.fromTransaction(transaction, signature, 0, RING);
      const first = sealed.capsules[0];
      const binding = bindings[0];
      const other = bindings[1];
      if (
        first === undefined ||
        binding === undefined ||
        other === undefined ||
        owners[0] === undefined
      )
        throw new Error("missing confirmation");
      expect(openRingDepositOpening(first, auditor, owners[0], binding).ownerKey).toEqual(ownerKey);
      const forged: unknown = Object.create(ConfirmedDeposit.prototype);
      expect(ConfirmedDeposit.is(forged)).toBe(false);
      expect(ConfirmedDeposit.is(binding)).toBe(true);
      for (const offset of [0, 32, 64, 95]) {
        const ciphertext = checkedBytes<Bytes96>(first.ciphertext, 96, "deposit ciphertext");
        ciphertext[offset] = (ciphertext[offset] ?? 0) ^ 1;
        expect(() =>
          openRingDepositOpening({ ...first, ciphertext }, auditor, owners[0]!, binding),
        ).toThrow("RING_AUDIT_MESSAGE");
      }
      expect(() =>
        openRingDepositOpening(
          { ...first, recipientCiphertext: Uint8Array.of(10) },
          auditor,
          owners[0]!,
          binding,
        ),
      ).toThrow("RING_AUDIT_MESSAGE");
      expect(() => openRingDepositOpening(first, auditor, owners[0]!, other)).toThrow(
        "RING_AUDIT_MESSAGE",
      );
      expect(() => ConfirmedDeposit.fromTransaction(transaction, signature, 1, RING)).toThrow(
        "RING_ORIGIN_DECODE",
      );
      expect(() =>
        ConfirmedDeposit.fromTransaction(transaction, "2".repeat(87) as Signature, 0, RING),
      ).toThrow("RING_ORIGIN_DECODE");
      expect(() =>
        ConfirmedDeposit.fromTransaction(
          {
            ...transaction,
            meta: { ...transaction.meta, err: { InstructionError: [0, 1] } },
          },
          signature,
          0,
          RING,
        ),
      ).toThrow("RING_ORIGIN_DECODE");
      const source = transaction.meta.innerInstructions[0]?.instructions[0];
      if (source === undefined) throw new Error("missing source");
      const unaudited = {
        ...transaction,
        transaction: {
          ...transaction.transaction,
          message: {
            ...transaction.transaction.message,
            instructions: [{ ...source, programIdIndex: 0 }],
          },
        },
      };
      expect(ConfirmedDeposit.fromTransaction(unaudited, signature, 0, RING)).toEqual([]);
    } finally {
      sealed.ephemeralSecret.fill(0);
      auditor.destroy();
    }
  });
});
