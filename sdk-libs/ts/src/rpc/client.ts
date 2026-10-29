import {
  ZolanaApi,
  resolveClientEndpoints,
  fromClientCause,
  checkedServiceUrl,
  ProverClient,
} from "@heliuslabs/zolana/internal";
import {
  initializePoseidon,
  type Address,
  type Bytes32,
  type RequestContext,
  ClientError,
  type ZolanaClientConfig,
} from "@heliuslabs/zolana";
import { ZolanaClient, type ProvingKeyReport } from "@heliuslabs/zolana/client";

import { RingError } from "../protocol/error.js";
import { RingIndexer } from "./indexer.js";
import type {
  RecordWrite,
  RingApplyProofInputs,
  RingMemberOpenings,
  RingMemberPage,
  RingMemberPageRequest,
  RingMemberProofRequest,
  RingMemberRecordResult,
  RingProver,
  RingQueueState,
  RingRecordPool,
  RingRecordPoolRequest,
  RingRecordReader,
  RingRegistryState,
  StorageMemberOpenings,
  StorageMemberPage,
  StorageOpeningsRequest,
  StoragePageRequest,
  StorageRecordPool,
  StorageRecordPoolRequest,
} from "./ports.js";
import { CustomRingProver } from "./prover/client.js";
import { customRingProof } from "./prover/proof.js";
import type { RingProofRequest } from "./prover/ring.js";

/** Initializes Poseidon, the constructor alone does not. */
export async function createCustomRingClient(
  config: ZolanaClientConfig = {},
): Promise<CustomRingClient> {
  await initializePoseidon();
  return new CustomRingClient(config);
}

export class CustomRingClient extends ZolanaClient implements RingProver, RingRecordReader {
  readonly #ringProver: CustomRingProver;
  readonly #ringIndexer: RingIndexer;

  constructor(config: ZolanaClientConfig) {
    super(config);
    // The parent's prover keeps one attested session for both rails.
    if (!(this.proofService instanceof ProverClient)) {
      throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field: "proverUrl" } });
    }
    this.#ringProver = new CustomRingProver(this.proofService);
    const endpoints = resolveClientEndpoints(config);
    const url = checkedServiceUrl(
      endpoints.photon,
      endpoints.photonField,
      config.allowInsecureHttp ?? false,
    );
    this.#ringIndexer = new RingIndexer(
      new ZolanaApi({
        url,
        ...(config.apiKey === undefined ? {} : { apiKey: config.apiKey }),
        ...(config.fetch === undefined ? {} : { fetch: config.fetch }),
      }),
    );
  }

  getRingMemberRecord(
    request: RingMemberProofRequest,
    context?: RequestContext,
  ): Promise<RingMemberRecordResult> {
    return this.#ringIndexer.getRingMemberRecord(request, context);
  }

  getRingMemberRecords(
    request: RingMemberPageRequest,
    context?: RequestContext,
  ): Promise<RingMemberPage> {
    return this.#ringIndexer.getRingMemberRecords(request, context);
  }

  getRingMemberRegistryRoot(
    request: Readonly<{ ringProgramId: Address }>,
    context?: RequestContext,
  ): Promise<RingRegistryState> {
    return this.#ringIndexer.getRingMemberRegistryRoot(request, context);
  }

  getRingMemberOpenings(
    request: Readonly<{
      ringProgramId: Address;
      members: readonly Bytes32[];
      expectedRoot: Bytes32;
    }>,
    context?: RequestContext,
  ): Promise<RingMemberOpenings> {
    return this.#ringIndexer.getRingMemberOpenings(request, context);
  }

  getRingRecordPool(
    request: RingRecordPoolRequest,
    context?: RequestContext,
  ): Promise<RingRecordPool> {
    return this.#ringIndexer.getRingRecordPool(request, context);
  }

  getStorageMemberOpenings(
    request: StorageOpeningsRequest,
    context?: RequestContext,
  ): Promise<StorageMemberOpenings> {
    return this.#ringIndexer.getStorageMemberOpenings(request, context);
  }

  getStorageMemberRecords(
    request: StoragePageRequest,
    context?: RequestContext,
  ): Promise<StorageMemberPage> {
    return this.#ringIndexer.getStorageMemberRecords(request, context);
  }

  getStorageRecordPool(
    request: StorageRecordPoolRequest,
    context?: RequestContext,
  ): Promise<StorageRecordPool> {
    return this.#ringIndexer.getStorageRecordPool(request, context);
  }

  getRingRecordQueue(
    request: Readonly<{ ringProgramId: Address }>,
    context?: RequestContext,
  ): Promise<RingQueueState> {
    return this.#ringIndexer.getRingRecordQueue(request, context);
  }

  getRingApplyProofInputs(
    request: Readonly<{ ringProgramId: Address; authorityWrites: readonly RecordWrite[] }>,
    context?: RequestContext,
  ): Promise<RingApplyProofInputs> {
    return this.#ringIndexer.getRingApplyProofInputs(request, context);
  }

  /** One ring proof, the 192-byte `CustomRingProof` the ring program verifies. */
  proveRing(request: RingProofRequest, context?: RequestContext): Promise<Uint8Array> {
    return proving(async () => customRingProof(await this.#ringProver.proveRing(request, context)));
  }

  checkRingProvingKeys(context?: RequestContext): Promise<ProvingKeyReport> {
    return proving(() => this.#ringProver.checkProvingKeys(context));
  }
}

async function proving<T>(run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (cause) {
    throw cause instanceof RingError ? cause : fromClientCause(cause);
  }
}
