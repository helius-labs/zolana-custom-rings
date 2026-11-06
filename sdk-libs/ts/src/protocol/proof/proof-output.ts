import {
  createProofOutput,
  type ProofOutputInit,
  type ProofOutputUtxo,
} from "@heliuslabs/spr/transaction";

export function withOutputFields(
  output: ProofOutputUtxo,
  patch: Partial<ProofOutputInit>,
): ProofOutputUtxo {
  return createProofOutput({
    ...(output.ownerAddress === undefined ? {} : { ownerAddress: output.ownerAddress }),
    asset: output.asset,
    ...(output.mint === undefined ? {} : { mint: output.mint }),
    amount: output.amount,
    blinding: output.blinding,
    data: output.data,
    ...(output.dataHash === undefined ? {} : { dataHash: output.dataHash }),
    ...(output.ringDataHash === undefined ? {} : { ringDataHash: output.ringDataHash }),
    ...(output.ringProgramId === undefined ? {} : { ringProgramId: output.ringProgramId }),
    ...(output.ownerTag === undefined ? {} : { ownerTag: output.ownerTag }),
    ...(output.cacheSlot === undefined ? {} : { cacheSlot: output.cacheSlot }),
    ...(output.compact === true ? { compact: true } : {}),
    ...patch,
  });
}
