import {
  SprApi,
  resolveClientEndpoints,
  fromClientCause,
  checkedServiceUrl,
  ProverClient,
} from "@heliuslabs/spr/internal";
import {
  initializePoseidon,
  type RequestContext,
  ClientError,
  type SprClientConfig,
} from "@heliuslabs/spr";
import { SprClient, type ProvingKeyReport } from "@heliuslabs/spr/client";

import type {
  PendingEnrollments,
  PendingEnrollmentsRequest,
  TrackingOpenings,
  TrackingOpeningsRequest,
  TrackingRecordPoolRequest,
} from "../protocol/indexer/tracking-codec.js";
import type { ServedTrackingPool } from "../protocol/membership/tracking.js";
import { RingError } from "../protocol/error.js";
import { RingIndexer } from "./indexer.js";
import type {
  RingProver,
  RingRecordReader,
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

export type CustomRingClientConfig = Omit<SprClientConfig, "provingKeys"> & {
  readonly provingKeys?: never;
};

/** Initializes Poseidon, the constructor alone does not. */
export async function createCustomRingClient(
  config: CustomRingClientConfig = {},
): Promise<CustomRingClient> {
  await initializePoseidon();
  return new CustomRingClient(config);
}

export class CustomRingClient extends SprClient implements RingProver, RingRecordReader {
  readonly #ringProver: CustomRingProver;
  readonly #ringIndexer: RingIndexer;

  constructor(config: CustomRingClientConfig) {
    if (
      typeof config === "object" &&
      config !== null &&
      "provingKeys" in config &&
      config.provingKeys !== undefined
    ) {
      throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field: "provingKeys" } });
    }
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
      new SprApi({
        url,
        ...(config.apiKey === undefined ? {} : { apiKey: config.apiKey }),
        ...(config.fetch === undefined ? {} : { fetch: config.fetch }),
      }),
    );
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

  getTrackingOpenings(
    request: TrackingOpeningsRequest,
    context?: RequestContext,
  ): Promise<TrackingOpenings> {
    return this.#ringIndexer.getTrackingOpenings(request, context);
  }

  getTrackingRecordPool(
    request: TrackingRecordPoolRequest,
    context?: RequestContext,
  ): Promise<ServedTrackingPool> {
    return this.#ringIndexer.getTrackingRecordPool(request, context);
  }

  getPendingEnrollments(
    request: PendingEnrollmentsRequest,
    context?: RequestContext,
  ): Promise<PendingEnrollments> {
    return this.#ringIndexer.getPendingEnrollments(request, context);
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
