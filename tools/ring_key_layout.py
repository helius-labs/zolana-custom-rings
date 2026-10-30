"""Filesystem layout for generated ring verifier modules."""

from pathlib import Path


def verifier_relative_path(module: str) -> Path:
    name = module.removesuffix(".rs")
    file = f"{name}.rs"
    if name.startswith("audit_anonymous_entry_"):
        return Path("audit/entry") / file
    if name.startswith("audit_anonymous_"):
        outputs = name.split("_")[4]
        if outputs not in {"2", "4", "8"}:
            raise ValueError(f"unknown anonymous audit shape: {module}")
        return Path("audit/anonymous") / f"outputs_{outputs}" / file
    if name.startswith("audit_"):
        return Path("audit") / file
    if name.startswith("policy_member_"):
        parts = name.split("_")
        if len(parts) < 4 or parts[3] not in {"2", "4", "8", "16"}:
            raise ValueError(f"unknown member policy shape: {module}")
        scope = parts[-3]
        if scope not in {"own", "curator"}:
            raise ValueError(f"unknown member policy scope: {module}")
        return Path("policy/member") / f"outputs_{parts[3]}" / scope / file
    if name.startswith("policy_delegate_"):
        return Path("policy/delegate") / file
    if name.startswith("deposit_"):
        return Path("deposit") / file
    if name.startswith("merge_"):
        return Path("merge") / file
    if name.startswith(("apply_records_", "register_key_", "withdrawal_exemption_")):
        return Path("records") / file
    raise ValueError(f"unknown ring verifier family: {module}")
