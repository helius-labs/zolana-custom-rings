# Zolana custom rings workspace
set dotenv-load

# zolana's recipes run inside the submodule, `just zolana::build-programs`.
mod zolana

export RUST_BACKTRACE := env_var_or_default("RUST_BACKTRACE", "0")
sbf-tools-version := env_var_or_default("SBF_TOOLS_VERSION", "v1.54")

# Per-clone port isolation, the same scheme and .env as zolana's justfile.
export ZOLANA_PORT_OFFSET := env_var_or_default("ZOLANA_PORT_OFFSET", "0")
localnet-rpc-port := env_var_or_default("ZOLANA_LOCALNET_RPC_PORT", `echo $((8899 + ${ZOLANA_PORT_OFFSET:-0}))`)
localnet-photon-port := env_var_or_default("ZOLANA_LOCALNET_PHOTON_PORT", `echo $((8784 + ${ZOLANA_PORT_OFFSET:-0}))`)
localnet-prover-port := env_var_or_default("ZOLANA_LOCALNET_PROVER_PORT", `echo $((3001 + ${ZOLANA_PORT_OFFSET:-0}))`)
localnet-ring-rpc-port := env_var_or_default("ZOLANA_LOCALNET_RING_RPC_PORT", `echo $((8785 + ${ZOLANA_PORT_OFFSET:-0}))`)
localnet-ring-indexer-port := env_var_or_default("ZOLANA_LOCALNET_RING_INDEXER_PORT", `echo $((8786 + ${ZOLANA_PORT_OFFSET:-0}))`)
stop-localnet-backends := "for port in " + localnet-rpc-port + " $((" + localnet-rpc-port + " + 1)); do lsof -t -i tcp:$port -s tcp:listen 2>/dev/null | xargs kill -9 2>/dev/null || true; done"
localnet-rpc-url := env_var_or_default("ZOLANA_LOCALNET_URL", "http://127.0.0.1:" + localnet-rpc-port)
localnet-photon-url := env_var_or_default("ZOLANA_LOCALNET_PHOTON_URL", "http://127.0.0.1:" + localnet-photon-port)
# Clients read Photon through the ring indexer.
localnet-ring-indexer-url := env_var_or_default("ZOLANA_LOCALNET_RING_INDEXER_URL", "http://127.0.0.1:" + localnet-ring-indexer-port)
localnet-prover-url := env_var_or_default("ZOLANA_PROVER_URL", "http://127.0.0.1:" + localnet-prover-port)
photon-bin := env_var_or_default("ZOLANA_PHOTON_BIN", "target/debug/photon")
export RING_INDEXER_BIN := env_var_or_default("RING_INDEXER_BIN", justfile_directory() / "target/debug/ring-indexer")
# join keeps an absolute ZOLANA_SPP_KEYS_DIR as given.
spp-keys-dir := join(justfile_directory(), env_var_or_default("ZOLANA_SPP_KEYS_DIR", "zolana/prover/server/proving-keys"))
ring-keys-lock := "prover/ring/proving-keys.lock"
custom-ring-keys := `python3 -c "import json;print(' '.join(sorted(json.load(open('prover/ring/proving-keys.lock'))['keys'])))"`

export ZOLANA_PROVER_URL := localnet-prover-url
export PROVER_INDEXER_URL := localnet-ring-indexer-url
# Every prover a recipe here starts is the ring prover.
# Any genesis address works, the shared ring binary serves it.
export CUSTOM_RING_PROGRAM_ID := env_var_or_default("CUSTOM_RING_PROGRAM_ID", "9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh")
export PROVER_BIN := justfile_directory() / "target/prover-server"
# Mirrored by GENESIS_PROGRAMS in cli/src/commands/ring/localnet.rs.
ring-genesis-programs := "--sbf-program 6cGXszer5keoaWm8Co5G9f4KGBThuGz4NsKTqYij1emg target/deploy/storage_program.so"
sdk-lib-crates := "zolana-ring-client zolana-ring-indexer zolana-ring-transaction zolana-ring-rpc custom-ring-sdk custom-ring-cli custom-ring-interface zolana-ring-policy zolana-ring-member-registry"

default:
    @just --list

# === Build ===

build-programs: build-spp-programs build-ring-program

# Only the zolana programs the ring stack deploys.
build-spp-programs:
    #!/usr/bin/env bash
    set -euo pipefail
    [[ -z "${ZOLANA_PREBUILT:-}" ]] || exit 0
    cd zolana
    # The in-proof owner rail needs SPP's ring-confidential-eddsa feature.
    SBF_TOOLS_VERSION={{sbf-tools-version}} tools/build-programs.sh \
        --manifest-path programs/user-registry/Cargo.toml -- --locked --features bpf-entrypoint
    SBF_TOOLS_VERSION={{sbf-tools-version}} tools/build-programs.sh \
        --manifest-path programs/shielded-pool/Cargo.toml -- --locked \
        --features bpf-entrypoint,ring-confidential-eddsa

build-ring-program: build-storage-program
    #!/usr/bin/env bash
    [[ -z "${ZOLANA_PREBUILT:-}" ]] || exit 0
    SBF_TOOLS_VERSION={{sbf-tools-version}} zolana/tools/build-programs.sh \
        --manifest-path programs/custom-ring/Cargo.toml -- --locked --features bpf-entrypoint

build-storage-program:
    #!/usr/bin/env bash
    [[ -z "${ZOLANA_PREBUILT:-}" ]] || exit 0
    SBF_TOOLS_VERSION={{sbf-tools-version}} zolana/tools/build-programs.sh \
        --manifest-path programs/storage/Cargo.toml -- --locked --features bpf-entrypoint

# Skipped when ZOLANA_SPP_PROGRAM_SO and ZOLANA_USER_REGISTRY_SO name builds.
_spp-programs:
    #!/usr/bin/env bash
    set -euo pipefail
    [[ -n "${ZOLANA_SPP_PROGRAM_SO:-}" && -n "${ZOLANA_USER_REGISTRY_SO:-}" ]] && exit 0
    {{just_executable()}} build-spp-programs

build-cli:
    #!/usr/bin/env bash
    [[ -z "${ZOLANA_PREBUILT:-}" ]] || exit 0
    cargo build --locked -p custom-ring-cli --target-dir target

# zolana's Photon, skipped when ZOLANA_PHOTON_BIN names a build.
build-photon:
    #!/usr/bin/env bash
    [[ -z "${ZOLANA_PREBUILT:-}" && -z "${ZOLANA_PHOTON_BIN:-}" ]] || exit 0
    cargo build --locked --manifest-path zolana/Cargo.toml -p photon-indexer --bin photon \
        --features surfpool-fixture --target-dir target

# The fixture feature only acts under ZOLANA_RING_SURFPOOL_FIXTURE=1.
build-ring-indexer:
    #!/usr/bin/env bash
    [[ -z "${ZOLANA_PREBUILT:-}" ]] || exit 0
    cargo build --locked -p ring-indexer --features surfpool-fixture --target-dir target

build-ring-rpc:
    #!/usr/bin/env bash
    [[ -z "${ZOLANA_PREBUILT:-}" ]] || exit 0
    cargo build --locked -p zolana-ring-rpc --target-dir target

build-zolana-tools: zolana::build-cli
    cargo build --manifest-path zolana/Cargo.toml -p xtask --target-dir zolana/target

build-ring-tools: build-ring-indexer build-cli build-ring-rpc

# The zolana and ring clis, the prover server, xtask, Photon, the ring indexer and the ring rpc.
build-localnet-tools: build-zolana-tools build-prover-server build-photon build-ring-tools

build-localnet-archives dir="target/nextest-archives":
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p {{dir}}
    cargo nextest archive -p custom-ring-test-validator --test ring --test shared_sources --test policy_rules --test policy_repin --archive-file {{dir}}/custom-ring-test-validator.tar.zst

# === Tests ===

# Everything that needs nothing running.
test-hermetic: test-program-fast test-sdk-libs test-ring-indexer

test-program-fast: build-programs
    cargo nextest run -p custom-ring-program -p storage-program --tests

test-sdk-libs:
    cargo nextest run {{prepend("-p ", sdk-lib-crates)}}

test-ring-indexer:
    cargo nextest run -p ring-indexer

# Custom-ring lifecycle on a local validator (program-tests/custom-ring/tests/ring.rs).
test-custom-ring-validator filter="all()" *args: fetch-custom-ring-keys build-prover-server build-programs zolana::build-cli zolana::ensure-smart-account zolana::ensure-surfpool
    #!/usr/bin/env bash
    set -euo pipefail
    program_ids=$(cd zolana && tools/ci/xtask.sh program-ids)
    eval "$program_ids"
    : "${SHIELDED_POOL_PROGRAM_ID:?xtask did not emit SHIELDED_POOL_PROGRAM_ID}"
    export SHIELDED_POOL_PROGRAM_ID
    ZOLANA_SPP_KEYS_DIR="{{spp-keys-dir}}" bash tools/test-ring-controls.sh ring -E '{{filter}}' {{args}}

# Two-ring shared policy source lifecycle on a local validator.
test-custom-ring-shared: (_custom-ring-suite "shared_sources")

# Policy rule lifecycle over the rule table pinned from ring.toml.
test-custom-ring-rules: (_custom-ring-suite "policy_rules")

# UpdatePolicy rewrites the rule table of a live ring.
test-custom-ring-repin: (_custom-ring-suite "policy_repin")

_custom-ring-suite test: fetch-custom-ring-keys build-prover-server build-programs zolana::build-cli zolana::ensure-smart-account zolana::ensure-surfpool
    #!/usr/bin/env bash
    set -euo pipefail
    program_ids=$(cd zolana && tools/ci/xtask.sh program-ids)
    eval "$program_ids"
    : "${SHIELDED_POOL_PROGRAM_ID:?xtask did not emit SHIELDED_POOL_PROGRAM_ID}"
    export SHIELDED_POOL_PROGRAM_ID
    ZOLANA_SPP_KEYS_DIR="{{spp-keys-dir}}" bash tools/test-ring-controls.sh {{test}}

# === Keys ===

# zolana's prover, built from the ring Go module.
build-prover-server:
    #!/usr/bin/env bash
    [[ -z "${ZOLANA_PREBUILT:-}" ]] || exit 0
    mkdir -p target
    cd prover && sh ../zolana/prover/server/build-release.sh ../target/prover-server ./cmd/prover

# Go circuit and proof tests.
test-custom-ring:
    cd prover && go test ./... -count=1

# Ring keys and transfer shapes must match their lockfiles.
fetch-custom-ring-keys:
    #!/usr/bin/env bash
    set -euo pipefail
    keys_dir="{{spp-keys-dir}}"
    mkdir -p "$keys_dir"
    temp_dir="$(mktemp -d)"
    trap 'rm -rf "$temp_dir"' EXIT
    pinned() {
        python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["keys"][sys.argv[2]]["sha256"])' "$1" "$2"
    }
    digest() {
        shasum -a 256 "$1" | awk '{ print $1 }'
    }
    fetch() {
        lock="$1" name="$2" url="$3"
        want="$(pinned "$lock" "$name")"
        [[ -f "$keys_dir/$name" && "$(digest "$keys_dir/$name")" == "$want" ]] && return
        echo "Downloading $name" >&2
        curl -fsSL --retry 3 --retry-max-time 60 --connect-timeout 10 --max-time 300 \
            "$url" -o "$temp_dir/$name"
        got="$(digest "$temp_dir/$name")"
        if [[ "$got" != "$want" ]]; then
            echo "$url hashes to $got, $lock pins $want" >&2
            exit 1
        fi
        install -m 0644 "$temp_dir/$name" "$keys_dir/$name"
    }
    release_url="${ZOLANA_RING_KEYS_URL:-$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["release"])' "{{ring-keys-lock}}")}"
    for name in {{custom-ring-keys}}; do
        fetch "{{ring-keys-lock}}" "$name" "$release_url/$name"
    done
    spp_lock="zolana/prover/server/prover/provingkeys/proving-keys.lock"
    spp_url="${ZOLANA_PROVING_KEYS_URL:-https://d3gbdb0egjwcw9.cloudfront.net}/$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["prefix"])' "$spp_lock")"
    for name in transfer_ring_1_2.key transfer_ring_2_2.key; do
        fetch "$spp_lock" "$name" "$spp_url/$name"
    done

# The committed verifying keys must be the export of the pinned proving keys.
check-custom-ring-keys: fetch-custom-ring-keys build-prover-server
    #!/usr/bin/env bash
    set -euo pipefail
    export_dir="$(mktemp -d)"
    trap 'rm -rf "$export_dir"' EXIT
    for key in {{custom-ring-keys}}; do
        module="${key#custom_ring_}"
        module="${module%.key}_verifying_key.rs"
        target/prover-server export-vk --keys-file "{{spp-keys-dir}}/$key" --output "$export_dir/$key.vkbin" >/dev/null
        cargo run -q --manifest-path zolana/Cargo.toml -p xtask -- bsb22-vk "$export_dir/$key.vkbin" "{{spp-keys-dir}}/$key" "$export_dir" "$module" >/dev/null
        rustfmt --config-path rustfmt.toml "$export_dir/$module"
        relative="$(python3 -c 'import sys; from tools.ring_key_layout import verifier_relative_path; print(verifier_relative_path(sys.argv[1]))' "$module")"
        cp "program-libs/interface/src/verifying_keys/$relative" "$export_dir/committed-$module"
        rustfmt --config-path rustfmt.toml "$export_dir/committed-$module"
        diff -u "$export_dir/committed-$module" "$export_dir/$module"
    done

# === Rings ===

# Create a ring directory, ring.toml and the program keypair.
ring-new *args:
    cargo run -q -p custom-ring-cli -- new {{args}}

# Local validator and services for a ring, ring creation is permissionless.
ring-localnet: check-custom-ring-keys build-programs zolana::build-cli build-photon build-ring-indexer
    #!/usr/bin/env bash
    set -euo pipefail
    eval "$(cd zolana && tools/ci/xtask.sh program-ids)"
    bin="zolana/target/debug/zolana"
    workdir="target/ring-localnet"
    rm -rf "$workdir"
    mkdir -p "$workdir"
    photon_bin="{{photon-bin}}"
    [[ "$photon_bin" = /* ]] || photon_bin="$PWD/$photon_bin"
    export ZOLANA_PHOTON_BIN="$photon_bin"
    export ZOLANA_PROVER_KEYS_DIR="{{spp-keys-dir}}"
    for port in {{localnet-rpc-port}} {{localnet-photon-port}} {{localnet-prover-port}} {{localnet-ring-indexer-port}}; do
      lsof -ti "tcp:$port" 2>/dev/null | xargs kill -9 2>/dev/null || true
    done
    sleep 2
    accounts_dir="$workdir/accounts"
    (cd zolana && tools/ci/xtask.sh generate-account-snapshots \
      --deploy-dir target/deploy --accounts-dir "$PWD/../$accounts_dir")
    # SIMD-0500 is off, the ring deploys as SBPF v0 like on devnet.
    "$bin" dev start --skip-prover \
      --rpc-port {{localnet-rpc-port}} --photon-port {{localnet-photon-port}} \
      --account-dir "$accounts_dir" --limit-ledger-size 5000000 \
      --sbf-program "$SHIELDED_POOL_PROGRAM_ID" zolana/target/deploy/shielded_pool_program.so \
      --sbf-program "$USER_REGISTRY_PROGRAM_ID" zolana/target/deploy/spr_user_registry.so \
      {{ring-genesis-programs}} \
      -- --deactivate-feature B8JJXCy5amZyWG9r7EnUYLwzXSXTxG7GZ1qZ1qggo83g
    tools/start-ring-indexer.sh "$workdir/ring-indexer" {{localnet-rpc-url}} {{localnet-photon-url}} \
      {{localnet-ring-indexer-port}}
    # The ring prover reads the key registry through the ring indexer.
    "$bin" dev prover start --prover-port {{localnet-prover-port}} \
      --indexer-url {{localnet-ring-indexer-url}}
    echo
    echo "localnet ready"
    echo "  rpc       {{localnet-rpc-url}}"
    echo "  indexer   {{localnet-ring-indexer-url}}  (the ring indexer in front of photon {{localnet-photon-url}})"
    echo "  prover    {{localnet-prover-url}}"
    echo "  ring rpc  http://127.0.0.1:{{localnet-ring-rpc-port}}  (started by 'just ring-rpc-derived')"

# Stops the validator, photon, the ring indexer, the prover and a ring RPC a ring's `just pipeline` left.
ring-localnet-stop:
    lsof -ti "tcp:{{localnet-rpc-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti "tcp:{{localnet-photon-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti "tcp:{{localnet-ring-indexer-port}}" 2>/dev/null | xargs kill 2>/dev/null || true
    lsof -ti "tcp:{{localnet-prover-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti "tcp:{{localnet-ring-rpc-port}}" 2>/dev/null | xargs kill 2>/dev/null || true
    {{stop-localnet-backends}}

# Photon, the ring indexer and the prover against a cluster from its current slot, RING_INDEXER_START_SLOT moves the ring indexer start.
ring-devnet-services rpc_url: check-custom-ring-keys build-prover-server build-photon build-ring-indexer
    #!/usr/bin/env bash
    set -euo pipefail
    workdir="target/ring-devnet"
    mkdir -p "$workdir"
    photon_bin="{{photon-bin}}"
    [[ "$photon_bin" = /* ]] || photon_bin="$PWD/$photon_bin"
    lsof -ti "tcp:{{localnet-photon-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti "tcp:{{localnet-prover-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
    sleep 1
    nohup "$photon_bin" --rpc-url "{{rpc_url}}" --port {{localnet-photon-port}} --start-slot latest \
      > "$workdir/photon.log" 2>&1 &
    nohup target/prover-server start --keys-dir "{{spp-keys-dir}}" \
      --prover-address 0.0.0.0:{{localnet-prover-port}} --auto-download=true \
      ${ZOLANA_PROVER_REDIS_URL:+--redis-url "$ZOLANA_PROVER_REDIS_URL"} \
      > "$workdir/prover.log" 2>&1 &
    # A slow start must look different from a hang.
    wait_for() {
      printf 'waiting for %-7s %s ' "$1" "$2"
      for _ in $(seq 1 120); do
        if curl -sf --max-time 5 "$3" >/dev/null 2>&1; then
          echo " ready"
          return 0
        fi
        printf '.'
        sleep 1
      done
      echo " timed out"
      echo "$1 did not become ready, see $4" >&2
      return 1
    }
    wait_for photon "{{localnet-photon-url}}" "{{localnet-photon-url}}/readiness" "$workdir/photon.log"
    wait_for prover "{{localnet-prover-url}}" "{{localnet-prover-url}}/health" "$workdir/prover.log"
    tools/start-ring-indexer.sh "$workdir/ring-indexer" "{{rpc_url}}" {{localnet-photon-url}} \
      {{localnet-ring-indexer-port}} "${RING_INDEXER_START_SLOT:-latest}"
    echo "devnet services ready"
    echo "  indexer   {{localnet-ring-indexer-url}}  (ring indexer, log $workdir/ring-indexer/ring-indexer.log)"
    echo "  photon    {{localnet-photon-url}}  (indexing {{rpc_url}}, log $workdir/photon.log)"
    echo "  prover    {{localnet-prover-url}}  (log $workdir/prover.log)"

# Stops photon, the ring indexer, the prover and a ring RPC started for devnet.
ring-devnet-services-stop:
    lsof -ti "tcp:{{localnet-photon-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti "tcp:{{localnet-ring-indexer-port}}" 2>/dev/null | xargs kill 2>/dev/null || true
    lsof -ti "tcp:{{localnet-prover-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti "tcp:{{localnet-ring-rpc-port}}" 2>/dev/null | xargs kill 2>/dev/null || true

# Foreground ring RPC in derived mode, one key per ring.
ring-rpc-derived:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p target/ring-localnet
    secret="target/ring-localnet/root.secret"
    if [ ! -f "$secret" ]; then
        cargo run -q -p zolana-ring-rpc -- keygen --out "$secret" --kind root
    fi
    cargo run -q -p zolana-ring-rpc -- serve --port {{localnet-ring-rpc-port}} \
        --indexer-url {{localnet-ring-indexer-url}} --rpc-url {{localnet-rpc-url}} \
        --root-secret-file "$secret"

# === Release and deploy ===

# Release the ring program, ring keys, ring-rpc and zolana-ring, `--upload --prerelease` publishes.
release tag *args: build-programs check-custom-ring-keys
    cargo run -p ring-xtask -- create-release --tag {{tag}} {{args}}

# Build one service image of tools/images.json and publish it by zolana's rules.
publish-image service *args:
    zolana/tools/publish-image.sh {{service}} {{args}}

# Isolated ECS test deployment of the prover and one ring RPC, every resource
# named zolana-rings-test-*, `RINGS_TEST_INDEXER_URL=... just rings-test up`.
rings-test command *args:
    tools/rings-test-deploy.sh {{command}} {{args}}

# Move the zolana pin, `just zolana-bump origin/main`.
zolana-bump rev:
    git -C zolana fetch origin
    git -C zolana checkout --detach {{rev}}
    git add zolana

# === TypeScript ===

# Ring TypeScript SDK formatting, linting, types, unit tests, and package build.
test-ts:
    npm run check:ts

# Ring TypeScript SDK flows against a fresh validator, Photon, ring indexer, ring prover and ring RPC.
test-ts-e2e *args: (_test-ts-live "test:ts:e2e" args)

_test-ts-live test-script *args: build-ring-program _spp-programs build-photon build-ring-indexer build-cli build-ring-rpc build-prover-server zolana::build-cli zolana::ensure-surfpool fetch-custom-ring-keys
    #!/usr/bin/env bash
    set -euo pipefail
    # A command substitution that exits nonzero is no `set -e` trigger, so the
    # ids are captured first and each one the recipe reads is required.
    program_ids="$(cd zolana && tools/ci/xtask.sh program-ids)"
    eval "$program_ids"
    : "${SHIELDED_POOL_PROGRAM_ID:?xtask did not emit SHIELDED_POOL_PROGRAM_ID}"
    : "${USER_REGISTRY_PROGRAM_ID:?xtask did not emit USER_REGISTRY_PROGRAM_ID}"
    : "${DEFAULT_TREE_ADDRESS:?xtask did not emit DEFAULT_TREE_ADDRESS}"
    ring_program_id="{{CUSTOM_RING_PROGRAM_ID}}"
    bin="zolana/target/debug/zolana"
    ring_cli="target/debug/zolana-ring"
    ring_rpc="target/debug/ring-rpc"
    workdir="target/ts-sdk-e2e"
    cleanup() {
      local status=$?
      if (( status != 0 )); then
        find "$workdir" test-ledger -name '*.log' -exec tail -n 200 {} + 2>/dev/null || true
      fi
      lsof -ti "tcp:{{localnet-rpc-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      lsof -ti "tcp:{{localnet-photon-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      lsof -ti "tcp:{{localnet-ring-indexer-port}}" 2>/dev/null | xargs kill 2>/dev/null || true
      lsof -ti "tcp:{{localnet-prover-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      lsof -ti "tcp:{{localnet-ring-rpc-port}}" 2>/dev/null | xargs kill 2>/dev/null || true
    }
    trap cleanup EXIT
    rm -rf "$workdir"
    mkdir -p "$workdir/scope"
    export ZOLANA_CONFIG_DIR="$PWD/$workdir"
    # The ring controls suite jumps the surfpool clock only inside a scoped runtime.
    export ZOLANA_PROCESS_SCOPE_DIR="$PWD/$workdir/scope"
    export SURFPOOL_BIN="$PWD/zolana/target/tools/surfpool"
    photon_bin="{{photon-bin}}"
    [[ "$photon_bin" = /* ]] || photon_bin="$PWD/$photon_bin"
    export ZOLANA_PHOTON_BIN="$photon_bin"
    spp_so="${ZOLANA_SPP_PROGRAM_SO:-zolana/target/deploy/shielded_pool_program.so}"
    [[ "$spp_so" = /* ]] || spp_so="$PWD/$spp_so"
    registry_so="${ZOLANA_USER_REGISTRY_SO:-zolana/target/deploy/spr_user_registry.so}"
    [[ "$registry_so" = /* ]] || registry_so="$PWD/$registry_so"
    # Surfpool gives empty slots synthetic hashes, only the fixture keeps ring blocks linked across the jump.
    export ZOLANA_RING_SURFPOOL_FIXTURE=1
    export ZOLANA_PROVER_KEYS_DIR="{{spp-keys-dir}}"
    cleanup
    sleep 2

    # The canonical protocol accounts of the current local build, loaded at
    # validator boot, leave ring creation permissionless.
    accounts_dir="$workdir/accounts"
    mkdir -p "$workdir/spp-deploy"
    ln -sf "$spp_so" "$workdir/spp-deploy/shielded_pool_program.so"
    (cd zolana && tools/ci/xtask.sh generate-account-snapshots \
      --deploy-dir "$PWD/../$workdir/spp-deploy" --accounts-dir "$PWD/../$accounts_dir")

    ring_dir="$workdir/ring"
    ring_origin="http://localhost:3000"
    ring_rpc_url="http://127.0.0.1:{{localnet-ring-rpc-port}}"
    mkdir -p "$ring_dir"
    solana-keygen new --no-bip39-passphrase --silent --force -o "$ring_dir/authority.json"
    ring_authority="$(solana-keygen pubkey "$ring_dir/authority.json")"

    # The ring program is loaded upgradeable, only its upgrade authority may
    # create the ring config.
    "$bin" dev start --skip-prover \
      --rpc-port {{localnet-rpc-port}} \
      --photon-port {{localnet-photon-port}} --account-dir "$accounts_dir" \
      --sbf-program "$SHIELDED_POOL_PROGRAM_ID" "$spp_so" \
      --sbf-program "$USER_REGISTRY_PROGRAM_ID" "$registry_so" \
      {{ring-genesis-programs}} \
      --upgradeable-program "$ring_program_id" target/deploy/custom_ring_program.so \
      "$ring_authority"
    tools/start-ring-indexer.sh "$workdir/ring-indexer" {{localnet-rpc-url}} {{localnet-photon-url}} \
      {{localnet-ring-indexer-port}}
    # The ring prover reads the key registry through the ring indexer.
    "$bin" dev prover start --prover-port {{localnet-prover-port}} \
      --indexer-url {{localnet-ring-indexer-url}}
    "$bin" config set --rpc-url {{localnet-rpc-url}} \
      --indexer-url {{localnet-ring-indexer-url}} --prover-url {{localnet-prover-url}} >/dev/null
    "$bin" wallet new --outfile "$workdir/authority.json"
    mint_output="$("$bin" dev pool test-mint --keypair "$workdir/authority.json" \
      --authority-path "$workdir/authority.json" --airdrop-lamports 20000000000 \
      --amount 1000000)"
    mint="$(sed -n 's/^ok test_mint mint=\([^ ]*\).*/\1/p' <<<"$mint_output")"
    token_account="$(sed -n 's/^ok test_mint .* token_account=\([^ ]*\).*/\1/p' <<<"$mint_output")"
    test -n "$mint"
    test -n "$token_account"
    token_2022_output="$("$bin" dev pool test-mint --keypair "$workdir/authority.json" \
      --authority-path "$workdir/authority.json" --token-program token2022 --amount 1000000)"
    token_2022_mint="$(sed -n 's/^ok test_mint mint=\([^ ]*\).*/\1/p' <<<"$token_2022_output")"
    token_2022_account="$(sed -n 's/^ok test_mint .* token_account=\([^ ]*\).*/\1/p' <<<"$token_2022_output")"
    test -n "$token_2022_mint"
    test -n "$token_2022_account"

    # The ring CLI parses both targets even though this ring only acts on localnet.
    cat > "$ring_dir/ring.toml" <<TOML
    name = "ts-sdk-e2e-ring"
    program_id = "$ring_program_id"
    authority_keypair = "$PWD/$ring_dir/authority.json"
    target = "localnet"

    [localnet]
    rpc = "{{localnet-rpc-url}}"
    indexer = "{{localnet-ring-indexer-url}}"
    prover = "{{localnet-prover-url}}"
    ring_rpc = "$ring_rpc_url"

    [devnet]
    rpc = "{{localnet-rpc-url}}"
    indexer = "{{localnet-ring-indexer-url}}"
    prover = "{{localnet-prover-url}}"
    ring_rpc = "$ring_rpc_url"

    # The released rows, the TS suites enrol every party in allow themselves.
    [[policy.rules]]
    subject = "output-owner"
    require = "allow"

    [[policy.rules]]
    subject = "sender"
    require = "allow"

    [[policy.rules]]
    subject = "output-owner"
    forbid = "block"

    [[policy.rules]]
    subject = "sender"
    forbid = "frozen"
    TOML
    # Derived mode, the suites deploy their own rings and take each auditor key from the service.
    "$ring_rpc" keygen --kind root --out "$ring_dir/root.secret"
    nohup "$ring_rpc" serve --port {{localnet-ring-rpc-port}} \
      --indexer-url {{localnet-ring-indexer-url}} --rpc-url {{localnet-rpc-url}} \
      --root-secret-file "$ring_dir/root.secret" \
      --allow-origin "$ring_origin" --webauthn-rp-id localhost \
      > "$workdir/ring-rpc.log" 2>&1 &
    printf 'waiting for ring rpc %s ' "$ring_rpc_url"
    for _ in $(seq 1 60); do
      if curl -sf --max-time 5 "$ring_rpc_url/health" >/dev/null 2>&1; then break; fi
      printf '.'
      sleep 1
    done
    if ! curl -sf --max-time 5 "$ring_rpc_url/health" >/dev/null 2>&1; then
      echo " timed out"
      echo "the ring rpc did not answer, see $workdir/ring-rpc.log" >&2
      exit 1
    fi
    echo " ready"
    # This recipe started the service, its key needs no pin.
    "$ring_cli" --config "$ring_dir/ring.toml" \
      init --auditor-pubkey-file "auditor.key.pub" --trust-ring-rpc
    # Reads are grant only, the ring authority included.
    "$ring_cli" --config "$ring_dir/ring.toml" \
      reader grant "$ring_authority"
    # The ring-status probe, otherwise exercised only against a hosted rpc.
    "$ring_cli" --config "$ring_dir/ring.toml" rpc-check

    # The root and workspace npm runs each strip one `--`.
    ZOLANA_LOCALNET_URL="{{localnet-rpc-url}}" \
      ZOLANA_LOCALNET_RPC_PORT="{{localnet-rpc-port}}" \
      ZOLANA_INDEXER_URL="{{localnet-ring-indexer-url}}" \
      ZOLANA_PROVER_URL="{{localnet-prover-url}}" \
      ZOLANA_TREE="$DEFAULT_TREE_ADDRESS" \
      ZOLANA_TEST_MINT="$mint" \
      ZOLANA_TEST_TOKEN_ACCOUNT="$token_account" \
      ZOLANA_TEST_TOKEN_2022_MINT="$token_2022_mint" \
      ZOLANA_TEST_TOKEN_2022_ACCOUNT="$token_2022_account" \
      ZOLANA_CLI_BIN="$PWD/$bin" \
      RING_PROGRAM_ID="$ring_program_id" \
      RING_RPC_URL="$ring_rpc_url" \
      RING_AUTHORITY_KEYPAIR="$PWD/$ring_dir/authority.json" \
      RING_ORIGIN="$ring_origin" \
      RING_PROGRAM_SO="$PWD/target/deploy/custom_ring_program.so" \
      USER_REGISTRY_PROGRAM_SO="$registry_so" \
      ZOLANA_TEST_AUTHORITY_WALLET="$PWD/$workdir/authority.json" \
      npm run "{{test-script}}" {{ if args == "" { "" } else { "-- -- " + args } }}

# === Formatting and linting ===

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

clippy:
    cargo clippy --workspace --all-targets -- -D warnings

check-all:
    cargo check --workspace --all-targets
