import { addressBytes, hashChain4, bigIntBytes } from "@heliuslabs/spr/internal";
import { solanaOwnerIdentity } from "@heliuslabs/spr/keypair";
import type { Address, Bytes32, RequestContext } from "@heliuslabs/spr/interface";
import type { ChainReader } from "@heliuslabs/spr/client";
import { assetField, type SettlementTransfer } from "@heliuslabs/spr/transaction";
import { splDestination } from "../operations/payments/anonymous.js";
import { RingError } from "../protocol/error.js";
import { domainField, RingDomain } from "../crypto/derivation/ring-domain.js";

export interface PolicyWithdrawal {
  readonly owner: Bytes32;
  readonly asset: Bytes32;
  readonly amount: bigint;
}
export function policyWithdrawalHash(legs: readonly PolicyWithdrawal[]): Bytes32 {
  return hashChain4([
    domainField(RingDomain.withdrawals),
    bigIntBytes(BigInt(legs.length)) as Bytes32,
    ...legs.flatMap((w) => [w.owner, w.asset, bigIntBytes(w.amount) as Bytes32]),
  ]) as Bytes32;
}
export async function readPolicyWithdrawals(
  client: Pick<ChainReader, "getAccount">,
  transfers: readonly SettlementTransfer[],
  tokenOwnerHint: Address | undefined,
  context?: RequestContext,
): Promise<
  Readonly<{ withdrawals: readonly PolicyWithdrawal[]; splWithdrawalOwners: readonly Bytes32[] }>
> {
  const withdrawals: PolicyWithdrawal[] = [];
  const splWithdrawalOwners: Bytes32[] = [];
  for (const transfer of transfers.filter((t) => !t.isDeposit)) {
    let owner: Address;
    if (transfer.kind === "sol") owner = transfer.userSolAccount;
    else {
      const read = await splDestination({ client, transfer, named: tokenOwnerHint }, context);
      if (read === undefined)
        throw new RingError("RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID", {
          details: { destination: transfer.tokenAccount },
        });
      owner = read.control.owner;
      splWithdrawalOwners.push(addressBytes(owner) as Bytes32);
    }
    withdrawals.push({
      owner: solanaOwnerIdentity(addressBytes(owner)) as Bytes32,
      asset: assetField(
        transfer.kind === "sol" ? ("11111111111111111111111111111111" as Address) : transfer.mint,
      ),
      amount: transfer.amount,
    });
  }
  return { withdrawals, splWithdrawalOwners };
}
