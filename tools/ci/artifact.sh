#!/usr/bin/env bash
# Cache key and paths of one CI build artifact, from the git index entries of its inputs and the toolchain env.
set -euo pipefail

name="${1:?artifact name}"
cd "$(git rev-parse --show-toplevel)"

common=(justfile tools/ci/artifact.sh)
case "$name" in
  zolana_programs)
    inputs=(zolana)
    paths=(zolana/target/deploy/shielded_pool_program.so zolana/target/deploy/spr_user_registry.so)
    ;;
  ring_program)
    inputs=(zolana Cargo.toml Cargo.lock rust-toolchain.toml .cargo programs program-libs)
    paths=(target/deploy/custom_ring_program.so target/deploy/storage_program.so)
    ;;
  zolana_tools)
    inputs=(zolana rust-toolchain.toml .cargo)
    paths=(zolana/target/debug/zolana zolana/target/debug/xtask)
    ;;
  photon)
    inputs=(zolana rust-toolchain.toml .cargo)
    paths=(target/debug/photon)
    ;;
  prover)
    inputs=(zolana prover)
    paths=(target/prover-server)
    ;;
  ring_tools)
    inputs=(. ':!sdk-libs/ts' ':!docs' ':!.github' ':!*.md' ':!package.json' ':!package-lock.json')
    paths=(target/debug/ring-indexer target/debug/zolana-ring target/debug/ring-rpc target/nextest-archives)
    ;;
  *)
    echo "unknown artifact $name" >&2
    exit 2
    ;;
esac

digest="$(
  {
    printf '%s\n' "${ImageOS:-local}" "${RUNNER_ARCH:-$(uname -m)}" "${AGAVE_VERSION:?}" "${SBF_TOOLS_VERSION:?}" \
      "${RUSTFLAGS:-}" "${CARGO_PROFILE_DEV_DEBUG:-}"
    git ls-files -s -- "${common[@]}" "${inputs[@]}"
  } | sha256sum | cut -c1-40
)"
echo "key=$name-$digest"
echo "path<<EOF"
printf '%s\n' "${paths[@]}"
echo "EOF"
