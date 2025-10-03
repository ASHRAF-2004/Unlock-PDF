#!/usr/bin/env python3
"""Compare our --info output with qpdf --show-encryption for sample PDFs."""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXECUTABLE = PROJECT_ROOT / "build" / "pdf_password_retriever"
PDF_FILES = [
    PROJECT_ROOT / "file.pdf",
    PROJECT_ROOT / "Practical_Test_02_MDS4123_FCM2.pdf",
    PROJECT_ROOT / "Visual_com.pdf",
    PROJECT_ROOT / "Test1.pdf",
]


@dataclass
class EncryptionSummary:
    revision: int
    permissions: int
    method: str
    permissions_flags: Dict[str, bool]


_PERMISSION_LABELS = [
    "extract for accessibility",
    "extract for any purpose",
    "print low resolution",
    "print high resolution",
    "modify document assembly",
    "modify forms",
    "modify annotations",
    "modify other",
    "modify anything",
]


def _run_command(command: List[str]) -> str:
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return result.stdout


def _parse_bool(value: str) -> bool:
    lowered = value.strip().lower()
    if lowered in {"allowed", "yes", "true"}:
        return True
    if lowered in {"not allowed", "no", "false"}:
        return False
    raise ValueError(f"Unexpected boolean token: {value!r}")


def _parse_our_output(text: str) -> EncryptionSummary:
    revision_match = re.search(r"Revision \(R\):\s*(-?\d+)", text)
    if not revision_match:
        raise ValueError("Failed to capture revision from our output")
    permissions_match = re.search(r"Permissions \(P\):\s*(-?\d+)", text)
    if not permissions_match:
        raise ValueError("Failed to capture permissions from our output")
    method_match = re.search(r"Method:\s*([A-Za-z0-9_-]+)", text)
    if not method_match:
        raise ValueError("Failed to capture method from our output")

    permissions_flags: Dict[str, bool] = {}
    for label in _PERMISSION_LABELS:
        pattern = rf"^\s*{re.escape(label)}:\s*(allowed|not allowed|not defined.*)$"
        match = re.search(pattern, text, re.MULTILINE)
        if not match:
            continue
        token = match.group(1)
        if token.startswith("not defined"):
            continue
        permissions_flags[label] = _parse_bool(token)

    return EncryptionSummary(
        revision=int(revision_match.group(1)),
        permissions=int(permissions_match.group(1)),
        method=method_match.group(1).upper(),
        permissions_flags=permissions_flags,
    )


def _parse_qpdf_output(text: str) -> EncryptionSummary:
    revision_match = re.search(r"^R =\s*(-?\d+)$", text, re.MULTILINE)
    if not revision_match:
        raise ValueError("Failed to capture revision from qpdf output")
    permissions_match = re.search(r"^P =\s*(-?\d+)$", text, re.MULTILINE)
    if not permissions_match:
        raise ValueError("Failed to capture permissions from qpdf output")
    method_match = re.search(r"stream encryption method:\s*([A-Za-z0-9_-]+)", text)
    if not method_match:
        raise ValueError("Failed to capture method from qpdf output")

    permissions_flags: Dict[str, bool] = {}
    for label in _PERMISSION_LABELS:
        pattern = rf"^{re.escape(label)}:\s*(allowed|not allowed)$"
        match = re.search(pattern, text, re.MULTILINE)
        if match:
            permissions_flags[label] = _parse_bool(match.group(1))

    return EncryptionSummary(
        revision=int(revision_match.group(1)),
        permissions=int(permissions_match.group(1)),
        method=method_match.group(1).upper(),
        permissions_flags=permissions_flags,
    )


def _compare_summaries(pdf_path: Path, ours: EncryptionSummary, qpdf_summary: EncryptionSummary) -> Dict[str, object]:
    mismatches: Dict[str, object] = {}

    if ours.revision != qpdf_summary.revision:
        mismatches["revision"] = {"ours": ours.revision, "qpdf": qpdf_summary.revision}
    if ours.permissions != qpdf_summary.permissions:
        mismatches["permissions"] = {"ours": ours.permissions, "qpdf": qpdf_summary.permissions}
    if ours.method != qpdf_summary.method:
        mismatches["method"] = {"ours": ours.method, "qpdf": qpdf_summary.method}

    for label in _PERMISSION_LABELS:
        ours_value = ours.permissions_flags.get(label)
        qpdf_value = qpdf_summary.permissions_flags.get(label)
        if ours_value is None or qpdf_value is None:
            continue
        if ours_value != qpdf_value:
            mismatches.setdefault("permissions_flags", {})[label] = {
                "ours": ours_value,
                "qpdf": qpdf_value,
            }

    if mismatches:
        mismatches["pdf"] = str(pdf_path.relative_to(PROJECT_ROOT))
    return mismatches


def main() -> None:
    if not EXECUTABLE.exists():
        raise SystemExit(f"Executable not found at {EXECUTABLE}. Build the project first.")

    all_mismatches: List[Dict[str, object]] = []
    for pdf in PDF_FILES:
        ours_output = _run_command([str(EXECUTABLE), "--info", str(pdf)])
        qpdf_output = _run_command(["qpdf", "--show-encryption", str(pdf)])

        ours_summary = _parse_our_output(ours_output)
        qpdf_summary = _parse_qpdf_output(qpdf_output)

        mismatches = _compare_summaries(pdf, ours_summary, qpdf_summary)
        if mismatches:
            all_mismatches.append(mismatches)

    if all_mismatches:
        print(json.dumps(all_mismatches, indent=2))
        raise SystemExit(1)

    print("All PDF encryption summaries match qpdf")


if __name__ == "__main__":
    main()
