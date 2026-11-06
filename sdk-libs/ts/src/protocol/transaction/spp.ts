/** What the ring reads of the pinned SPP, Rust `custom_ring_interface::spp`. */
import { SOL_MINT, type Address, type Bytes32 } from "@heliuslabs/spr";
import {
  assetField,
  bigIntToBytes,
  RING_AUTHORITY_WIDTHS,
  signedField,
  SOL_INTERFACE,
  SPP_SUPPORTED_SHAPES,
  type SettlementTransfer,
} from "@heliuslabs/spr/internal";
import { ClientError } from "@heliuslabs/spr/client";
import type { InterfaceTransfer, SettlementAccounts, Shape } from "@heliuslabs/spr/interface";

/** Rust `N_PUBLIC_SLOTS`, the public asset and amount slots every SPP circuit takes. */
export const N_PUBLIC_SLOTS = 3;

/** Rust `MAX_SPP_CPI_ACCOUNTS`, the ring program's ceiling for the SPP call. */
export const MAX_SPP_CPI_ACCOUNTS = 128;

const U64_MAX = (1n << 64n) - 1n;

/** The square shapes SPP keys the ring authority rail for, cost ordered. */
export const RING_AUTHORITY_SHAPES: readonly Shape[] = Object.freeze(
  SPP_SUPPORTED_SHAPES.filter(
    (shape) => shape.inputs === shape.outputs && RING_AUTHORITY_WIDTHS.includes(shape.inputs),
  ),
);

/** The widest spend a ring authority transaction takes. */
export const RING_AUTHORITY_MAX_INPUTS = Math.max(...RING_AUTHORITY_WIDTHS);

/** Rust `Shape::is_ring_authority`. */
export function isRingAuthorityShape(shape: Shape): boolean {
  return RING_AUTHORITY_SHAPES.some(
    (candidate) => candidate.inputs === shape.inputs && candidate.outputs === shape.outputs,
  );
}

/** SPP's public slots in first-use order, Rust `PublicSlots::fold`, zero past the used slots. */
export interface PublicSlots {
  /** `hash_bytes` of each mint, SOL under the zero address. */
  readonly assets: readonly Bytes32[];
  /** Signed nets, a withdrawal negative. */
  readonly nets: readonly bigint[];
  /** Sum of each asset's withdrawal legs, deposits excluded. */
  readonly gross: readonly bigint[];
}

export function publicSlots(transfers: readonly SettlementTransfer[]): PublicSlots {
  const nets = new Map<Address, bigint>();
  const gross = new Map<Address, bigint>();
  for (const transfer of transfers) {
    if (transfer.amount === 0n) throw new ClientError("CLIENT_PROVER_INPUT");
    const asset = transfer.kind === "sol" ? SOL_MINT : transfer.mint;
    const net = (nets.get(asset) ?? 0n) + (transfer.isDeposit ? transfer.amount : -transfer.amount);
    if (net > U64_MAX || -net > U64_MAX) throw new ClientError("CLIENT_PROVER_INPUT");
    nets.set(asset, net);
    gross.set(asset, (gross.get(asset) ?? 0n) + (transfer.isDeposit ? 0n : transfer.amount));
  }
  if (nets.size > N_PUBLIC_SLOTS) throw new ClientError("CLIENT_PROVER_INPUT");
  if ([...nets.values()].includes(0n)) throw new ClientError("CLIENT_PROVER_INPUT");
  const pad = <T>(values: readonly T[], zero: T): readonly T[] =>
    Object.freeze([
      ...values,
      ...Array.from({ length: N_PUBLIC_SLOTS - values.length }, () => zero),
    ]);
  return Object.freeze({
    assets: pad([...nets.keys()].map(assetField), new Uint8Array(32) as Bytes32),
    nets: pad([...nets.values()], 0n),
    gross: pad(
      [...nets.keys()].map((asset) => gross.get(asset) ?? 0n),
      0n,
    ),
  });
}

/** Rust `PublicSlots::gross_fields`, each gross as a right aligned u128. */
export function publicGrossFields(slots: PublicSlots): readonly Bytes32[] {
  return Object.freeze(slots.gross.map((gross) => bigIntToBytes(gross) as Bytes32));
}

/** Rust `PublicSlots::amount_fields`, a withdrawal is `q - |net|`. */
export function publicAmountFields(slots: PublicSlots): readonly Bytes32[] {
  return Object.freeze(
    slots.nets.map((net) => bigIntToBytes(signedField(net, "public amount")) as Bytes32),
  );
}

/** The wire leg of a public settlement, Rust `SettlementTransfer::interface_transfer`. */
export function interfaceTransferOf(transfer: SettlementTransfer): InterfaceTransfer {
  if (transfer.kind === "sol") {
    return transfer.isDeposit
      ? { kind: "solDeposit", amount: transfer.amount }
      : { kind: "solWithdrawal", amount: transfer.amount };
  }
  return transfer.isDeposit
    ? { kind: "splDeposit", amount: transfer.amount, splInterfaceBump: transfer.splInterfaceBump }
    : {
        kind: "splWithdrawal",
        amount: transfer.amount,
        splInterfaceBump: transfer.splInterfaceBump,
      };
}

/** The asset account then the user account one public leg commits, Rust `settlement_accounts`. */
export function settlementAccounts(transfer: SettlementTransfer): SettlementAccounts {
  return transfer.kind === "sol"
    ? { asset: SOL_INTERFACE, user: transfer.userSolAccount }
    : { asset: transfer.mint, user: transfer.tokenAccount };
}
