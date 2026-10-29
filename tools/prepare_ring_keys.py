#!/usr/bin/env python3
"""Prepare local proving keys without publishing a release.

Existing catalog keys are downloaded and hash checked. New circuits use gnark's
single-party production setup, matching the pinned protocol tooling. No setup
randomness is persisted. Run the key-loaded checks before exporting/publishing.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
import pathlib
import subprocess
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keys-dir", type=pathlib.Path, default=ROOT / "target/circuit-policy-keys")
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--fresh", action="store_true", help="set up each missing key, ignoring the lockfile pins")
    args = parser.parse_args()
    args.keys_dir = args.keys_dir.resolve()
    args.keys_dir.mkdir(parents=True, exist_ok=True)
    catalog = json.loads(subprocess.check_output(["go", "run", "./cmd/catalog"], cwd=ROOT / "prover"))
    previous = {"keys": {}} if args.fresh else json.loads((ROOT / "prover/ring/proving-keys.lock").read_text())

    def prepare(key):
        name = key["Circuit"]
        filename = name.replace("-", "_") + ".key"
        path = args.keys_dir / filename
        pinned = previous["keys"].get(filename)
        start = time.monotonic()
        if not path.exists():
            staging = args.keys_dir / ".setup"
            staging.mkdir(exist_ok=True)
            temporary = staging / filename
            if pinned is not None:
                url = previous["release"] + "/" + filename
                with urllib.request.urlopen(url, timeout=60) as source, temporary.open("wb") as out:
                    while chunk := source.read(1024 * 1024):
                        out.write(chunk)
            else:
                with (args.keys_dir / (filename + ".log")).open("w") as log:
                    subprocess.run(
                        [str(ROOT / "target/prover-server"), "setup-" + name, "--output", str(temporary)],
                        stdout=log,
                        stderr=subprocess.STDOUT,
                        check=True,
                        env={**os.environ, "GOMAXPROCS": "4"},
                    )
            if pinned is not None and digest(temporary) != pinned["sha256"]:
                raise RuntimeError("Downloaded key hash mismatch: " + filename)
            temporary.replace(path)
        sha256 = digest(path)
        if pinned is not None and sha256 != pinned["sha256"]:
            raise RuntimeError("Existing key hash mismatch: " + filename)
        size = path.stat().st_size
        print(f"{filename}: {size} bytes, {time.monotonic() - start:.1f}s", flush=True)
        return filename, {"sha256": sha256, "size": size, "source": "release"}

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        entries = dict(pool.map(prepare, catalog))
    manifest = {"keys": dict(sorted(entries.items()))}
    (args.keys_dir / "prepared-keys.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("Local keys prepared. Nothing published.", flush=True)


if __name__ == "__main__":
    main()
