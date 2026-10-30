/** The hidden owner's rail of an anonymous ring, mirrors Rust `pipeline::anonymous`. */
import {
  AccountState,
  getMultisigSize,
  getTokenDecoder,
  getTokenSize,
  type Token,
} from "@solana-program/token";
import { isOffCurveAddress, type MessagePartialSigner } from "@solana/kit";

import {
  ZERO_32,
  SYSTEM_PROGRAM,
  addressBytes,
  checkedAddress,
  encodeBase58,
  associatedTokenAddress,
  equalBytes,
} from "@heliuslabs/zolana/internal";
import type { ChainReader, RpcAccount } from "@heliuslabs/zolana/client";
import { SPL_TOKEN_2022_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID } from "@heliuslabs/zolana/interface";
import type { Address, Bytes32, Bytes64, RequestContext } from "@heliuslabs/zolana/interface";
import { ShieldedPublicKey } from "@heliuslabs/zolana/keypair";
import type { ShieldedAddress, SigningKey } from "@heliuslabs/zolana/keypair";
import type { SettlementTransfer, SppProofInputs } from "@heliuslabs/zolana/transaction";
import type { RingAddress } from "../../crypto/keys/ring-address.js";
import type { FirstContact } from "../../state/viewing-history.js";

import { RingError, type RingErrorCode } from "../../protocol/error.js";
import { spendsDefaultRing } from "../workflow/pipeline.js";
import { signMessage } from "../../rpc/ring-rpc.js";

/** The hidden owner's Ed25519 key, the signature lives inside the proof so the key may live in a wallet. Rust `AnonymousSpendSigner`. */
export interface AnonymousSpendSigner {
  publicKey(): ShieldedPublicKey;
  /** RFC 8032 Ed25519 over the transfer's 32-byte `messageHash`. */
  sign(message: Uint8Array, context?: RequestContext): Promise<Bytes64>;
}

/** An output paying a ring address, its tag by the spec view tag selection, Rust `AnonymousPayment`. */
export interface AnonymousPayment {
  readonly to: RingAddress;
  /** Paid until the pair is known. */
  readonly firstContact: FirstContact;
  readonly asset: Address;
  readonly amount: bigint;
}

/** Signs with an in-process key, the caller keeps and destroys it. */
export function signingKeySpendSigner(key: SigningKey): AnonymousSpendSigner {
  return Object.freeze({
    publicKey: () => key.publicKey(),
    sign: (message: Uint8Array) => Promise.resolve(key.sign(message)),
  });
}

/** Signs through a kit message signer, a wallet adapter's `signMessage`. */
export function messageSignerSpendSigner(signer: MessagePartialSigner): AnonymousSpendSigner {
  // A base58 address decodes to exactly 32 bytes.
  const publicKey = ShieldedPublicKey.fromEd25519(addressBytes(signer.address) as Bytes32);
  return Object.freeze({
    publicKey: () => publicKey,
    sign: (message: Uint8Array) => signMessage(signer, message),
  });
}

/**
 * The hidden owner signs no public slot, a public signature would undo the hiding. Returns the
 * owner's Ed25519 key.
 */
export function checkAnonymousSigner(
  input: Readonly<{
    signer: AnonymousSpendSigner;
    sender: ShieldedAddress;
    payer: Address;
  }>,
): Bytes32 {
  const signing = input.signer.publicKey();
  if (!(signing instanceof ShieldedPublicKey) || !signing.equals(input.sender.signingPublicKey))
    throw new RingError("RING_ANONYMOUS_SIGNER_MISMATCH");
  const owner = signing.ed25519();
  checkSignersHideOwner(owner, [input.payer]);
  return owner;
}

/** Rust `AnonymousPublicSignerLinksOwner`. */
export function checkSignersHideOwner(
  owner: Bytes32,
  signers: readonly (Address | undefined)[],
): void {
  if (signers.some((signer) => signer !== undefined && equalBytes(addressBytes(signer), owner)))
    throw new RingError("RING_ANONYMOUS_SIGNER_LINKS_OWNER");
}

/** Rust `AnonymousExits::token_owner`, the owner SPP binds for the SPL withdrawal, `undefined` without one. */
export async function anonymousExitTokenOwner(
  input: Readonly<{
    client: Pick<ChainReader, "getAccount">;
    transfers: readonly SettlementTransfer[];
    hiddenOwner: Bytes32;
    /** A missing exit token account must be the owner's associated token account. */
    tokenOwner?: Address;
  }>,
  context?: RequestContext,
): Promise<Address | undefined> {
  const hidden = encodeBase58(input.hiddenOwner);
  const named =
    input.tokenOwner === undefined ? undefined : checkedAddress(input.tokenOwner, "exitTokenOwner");
  const withdrawals = input.transfers.filter((transfer) => !transfer.isDeposit);
  if (named !== undefined && !withdrawals.some((transfer) => transfer.kind === "spl"))
    throw new RingError("RING_ANONYMOUS_EXIT_TOKEN_OWNER_MISMATCH");
  let tokenOwner: Address | undefined;
  for (const transfer of withdrawals) {
    if (transfer.kind === "sol") {
      await checkSolExit(
        { client: input.client, recipient: transfer.userSolAccount, hidden },
        context,
      );
      continue;
    }
    const owner = await splExitOwner({ client: input.client, transfer, hidden, named }, context);
    if (named !== undefined && named !== owner)
      throw new RingError("RING_ANONYMOUS_EXIT_NAMED_OWNER_MISMATCH", {
        details: { destination: transfer.tokenAccount, named, owner },
      });
    if (tokenOwner !== undefined && tokenOwner !== owner)
      throw new RingError("RING_ANONYMOUS_EXIT_DESTINATIONS_DIFFER");
    tokenOwner = owner;
  }
  return tokenOwner;
}

/** Rust `check_anonymous_slots`, only uncached noncompact notes in and Ed25519 owners out. */
export function checkAnonymousSlots(proofInputs: SppProofInputs): void {
  const inputOpen = proofInputs.inputUtxos.some(
    (input) => input.cacheSlot !== undefined || input.isCompact() || input.isAddress(),
  );
  const outputOpen = proofInputs.outputs.some(
    (output) =>
      output.cacheSlot !== undefined ||
      output.isCompact() ||
      (!output.isDummy() && output.ownerAddress?.signingPublicKey.signatureType() !== "ed25519"),
  );
  if (inputOpen || outputOpen) throw new RingError("RING_ANONYMOUS_SLOT_INVALID");
}

/** The entry key rebuilds every spent UTXO from its opening, Rust `check_entry_inputs`. */
export function checkEntryInputs(proofInputs: SppProofInputs): void {
  if (!spendsDefaultRing(proofInputs)) return;
  proofInputs.inputUtxos.forEach((input, index) => {
    if (input.isDummy()) return;
    if (input.utxo.ringProgramId !== undefined)
      throw new RingError("RING_ENTRY_RING_INPUT", { details: { index } });
    if (!carriesNoData([input.dataHash, input.ringDataHash]))
      throw new RingError("RING_ENTRY_INPUT_DATA", { details: { index } });
  });
}

/** Rust `carries_no_data`, a zero hash commits like an absent one. */
export function carriesNoData(hashes: readonly (Bytes32 | undefined)[]): boolean {
  return hashes.every((hash) => hash === undefined || equalBytes(hash, ZERO_32));
}

async function checkSolExit(
  input: Readonly<{
    client: Pick<ChainReader, "getAccount">;
    recipient: Address;
    hidden: Address;
  }>,
  context: RequestContext | undefined,
): Promise<void> {
  const { recipient } = input;
  if (recipient === input.hidden) throw exitRefused("RING_ANONYMOUS_EXIT_LINKS_OWNER", recipient);
  const account = await input.client.getAccount(recipient, context);
  // Data or a program owner could name a second key, SPP refuses both.
  if (account !== undefined && (account.owner !== SYSTEM_PROGRAM || account.data.length > 0))
    throw exitRefused("RING_ANONYMOUS_EXIT_ACCOUNT_HAS_DATA", recipient);
}

async function splExitOwner(
  input: Readonly<{
    client: Pick<ChainReader, "getAccount">;
    transfer: Extract<SettlementTransfer, { kind: "spl" }>;
    hidden: Address;
    named: Address | undefined;
  }>,
  context: RequestContext | undefined,
): Promise<Address> {
  const { transfer, hidden } = input;
  const destination = transfer.tokenAccount;
  const refused = (code: Parameters<typeof exitRefused>[0]) => exitRefused(code, destination);
  const read = await splDestination(input, context);
  if (read === undefined) throw refused("RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID");
  const { control, tokenProgram } = read;
  // An associated token account stays derivable from its first owner.
  const associated = await associatedTokenAddress(hidden, transfer.mint, tokenProgram);
  if ([destination, control.owner].includes(hidden) || associated === destination)
    throw refused("RING_ANONYMOUS_EXIT_LINKS_OWNER");
  // An off-curve address has no keypair, so it is never the hidden owner's key.
  if (!isOffCurveAddress(destination)) throw refused("RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_ON_CURVE");
  if (control.kind === "shared") throw refused("RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_SHARED");
  return control.owner;
}

export async function splDestination(
  input: Readonly<{
    client: Pick<ChainReader, "getAccount">;
    transfer: Extract<SettlementTransfer, { kind: "spl" }>;
    named: Address | undefined;
  }>,
  context: RequestContext | undefined,
): Promise<Readonly<{ control: TokenAccountControl; tokenProgram: Address }> | undefined> {
  const { mint, tokenAccount } = input.transfer;
  const account = await input.client.getAccount(tokenAccount, context);
  if (account !== undefined) {
    const control = tokenAccountControl(account, mint);
    return control === undefined ? undefined : { control, tokenProgram: account.owner };
  }
  if (input.named === undefined) return undefined;
  // The associated token program creates it with the named owner and no other authority.
  const tokenProgram = (await input.client.getAccount(mint, context))?.owner;
  if (tokenProgram === undefined || !isTokenProgram(tokenProgram)) return undefined;
  if ((await associatedTokenAddress(input.named, mint, tokenProgram)) !== tokenAccount)
    return undefined;
  return { control: { kind: "soleOwner", owner: input.named }, tokenProgram };
}

/** Every refusal names the destination it refused, Rust `exit_refused`. */
function exitRefused(
  code: Extract<RingErrorCode, `RING_ANONYMOUS_EXIT_${string}`>,
  destination: Address,
): RingError {
  return new RingError(code, { details: { destination } });
}

/** Rust `TokenAccountControl`. */
type TokenAccountControl = Readonly<{ kind: "soleOwner" | "shared"; owner: Address }>;

/** spl `AccountType::Account`, the byte after the base state of an account with extensions. */
const ACCOUNT_TYPE_ACCOUNT = 2;
const DELEGATE_TAG_OFFSET = 72;
const CLOSE_AUTHORITY_TAG_OFFSET = 129;

function isTokenProgram(program: Address): boolean {
  return program === SPL_TOKEN_PROGRAM_ID || program === SPL_TOKEN_2022_PROGRAM_ID;
}

/** Rust `TokenAccountState::unpack` over an initialized `mint` account of either token program. */
function tokenAccountControl(account: RpcAccount, mint: Address): TokenAccountControl | undefined {
  const { data } = account;
  const base = getTokenSize();
  if (
    !isTokenProgram(account.owner) ||
    data.length < base ||
    data.length === getMultisigSize() ||
    (data.length > base && data[base] !== ACCOUNT_TYPE_ACCOUNT)
  )
    return undefined;
  let token: Token;
  try {
    token = getTokenDecoder().decode(data.subarray(0, base));
  } catch {
    return undefined;
  }
  if (token.state !== AccountState.Initialized || token.mint !== mint) return undefined;
  // SPP counts any nonzero option tag as set, the kit decoder reads a tag above one as none.
  const sole = [DELEGATE_TAG_OFFSET, CLOSE_AUTHORITY_TAG_OFFSET].every((offset) =>
    data.subarray(offset, offset + 4).every((byte) => byte === 0),
  );
  return Object.freeze({ kind: sole ? "soleOwner" : "shared", owner: token.owner });
}
