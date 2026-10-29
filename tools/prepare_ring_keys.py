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


def filename_of(key):
    return key["Circuit"].replace("-", "_") + ".key"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keys-dir", type=pathlib.Path, default=ROOT / "target/circuit-policy-keys")
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--fresh", action="store_true", help="set up each missing key instead of downloading its pin")
    args = parser.parse_args()
    args.keys_dir = args.keys_dir.resolve()
    args.keys_dir.mkdir(parents=True, exist_ok=True)
    catalog = json.loads(subprocess.check_output(["go", "run", "./cmd/catalog"], cwd=ROOT / "prover"))
    lock = json.loads((ROOT / "prover/ring/proving-keys.lock").read_text())
    downloads = {} if args.fresh else lock["keys"]

    def existing(key):
        path = args.keys_dir / filename_of(key)
        return path.name, digest(path) if path.exists() else None

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        found = {name: sha256 for name, sha256 in pool.map(existing, catalog) if sha256 is not None}

    def record(name):
        return args.keys_dir / (name + ".sha256")

    def known(name, sha256):
        if name in downloads:
            return sha256 == downloads[name]["sha256"]
        recorded = record(name).read_text().strip() if record(name).exists() else None
        return sha256 in (lock["keys"].get(name, {}).get("sha256"), recorded)

    unknown = sorted(name for name, sha256 in found.items() if not known(name, sha256))
    if unknown:
        raise SystemExit("Existing keys match no lock pin or setup record, remove them: " + ", ".join(unknown))

    def prepare(key):
        name = key["Circuit"]
        filename = filename_of(key)
        path = args.keys_dir / filename
        pinned = downloads.get(filename)
        start = time.monotonic()
        sha256 = found.get(filename)
        if sha256 is None:
            staging = args.keys_dir / ".setup"
            staging.mkdir(exist_ok=True)
            temporary = staging / filename
            if pinned is not None:
                url = lock["release"] + "/" + filename
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
            sha256 = digest(temporary)
            if pinned is not None and sha256 != pinned["sha256"]:
                raise RuntimeError("Downloaded key hash mismatch: " + filename)
            if pinned is None:
                record(filename).write_text(sha256 + "\n")
            temporary.replace(path)
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
