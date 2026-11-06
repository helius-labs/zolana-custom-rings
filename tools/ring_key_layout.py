"""Filesystem layout for generated ring verifier modules."""

from pathlib import Path


def verifier_relative_path(module: str) -> Path:
    name = module.removesuffix(".rs")
    file = f"{name}.rs"
    if name.startswith("transfer_"):
        return Path("transfer") / file
    if name.startswith("merge_"):
        return Path("merge") / file
    if name.startswith(("apply_records_", "apply_enrollments_", "register_key_")):
        return Path("records") / file
    raise ValueError(f"unknown ring verifier family: {module}")
