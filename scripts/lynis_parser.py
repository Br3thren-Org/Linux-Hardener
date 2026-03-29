#!/usr/bin/env python3
"""
lynis_parser.py — Parse Lynis audit report .dat files and produce structured JSON summaries.

Usage:
    lynis_parser.py <pre_dat> <post_dat> <output_json> [distro] [auto_remediate_conf]
    lynis_parser.py --single <dat_file> <output_json>
"""

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# ─── Constants ────────────────────────────────────────────────────────────────

# Environment patterns that indicate a finding is not applicable in a
# headless/virtual/server context (no physical access, USB, GUI, etc.)
NOT_APPLICABLE_PATTERNS = re.compile(
    r"usb|physical|bios|bootloader|grub|partition|encrypt|luks",
    re.IGNORECASE,
)

# Keys in the .dat file that map to scalar metrics we care about
_DAT_KEY_HARDENING_INDEX = "hardening_index"
_DAT_KEY_TESTS_PERFORMED = "lynis_tests_done"
_DAT_KEY_LYNIS_VERSION   = "lynis_version"
_DAT_KEY_WARNING         = "warning"
_DAT_KEY_SUGGESTION      = "suggestion"

# ─── Core parsers ─────────────────────────────────────────────────────────────


def parse_finding(value: str) -> dict:
    """Parse a pipe-delimited Lynis finding string.

    Expected format: ``TEST_ID|Description|Details|Severity``

    Extra or missing fields are handled gracefully: surplus fields are ignored
    and missing fields default to an empty string.

    Args:
        value: Raw pipe-delimited string from a warning[] or suggestion[] entry.

    Returns:
        dict with keys: test_id, description, details, severity.

    Raises:
        ValueError: If *value* is empty or not a string.
    """
    if not isinstance(value, str):
        raise ValueError(f"parse_finding: expected str, got {type(value).__name__!r}")

    raw_value = value.strip()
    if not raw_value:
        raise ValueError("parse_finding: value must not be empty")

    parts = raw_value.split("|")
    # Pad to at least 4 fields so index access is always safe
    while len(parts) < 4:
        parts.append("")

    return {
        "test_id":     parts[0].strip(),
        "description": parts[1].strip(),
        "details":     parts[2].strip(),
        "severity":    parts[3].strip(),
    }


def parse_dat_file(dat_path: str) -> dict:
    """Parse a ``lynis-report.dat`` file into a structured dict.

    Reads the file line by line, splits each line on the **first** ``=`` sign,
    and extracts the following fields:

    * ``hardening_index``  – integer (0 if absent)
    * ``tests_performed``  – integer (0 if absent)
    * ``lynis_version``    – string (empty if absent)
    * ``warnings``         – list of dicts produced by :func:`parse_finding`
    * ``suggestions``      – list of dicts produced by :func:`parse_finding`

    Lines that are blank or start with ``#`` are skipped.  Lines without ``=``
    are skipped silently (malformed entries in the wild do occur).

    Args:
        dat_path: Path to the ``.dat`` file.

    Returns:
        Structured dict as described above.

    Raises:
        FileNotFoundError: If *dat_path* does not exist.
        ValueError: If a finding line cannot be parsed.
    """
    path = Path(dat_path)
    if not path.exists():
        raise FileNotFoundError(f"parse_dat_file: file not found: {dat_path!r}")

    hardening_index = 0
    tests_performed = 0
    lynis_version   = ""
    warnings        = []
    suggestions     = []

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            line = raw_line.strip()

            # Skip comments and blank lines
            if not line or line.startswith("#"):
                continue

            # Split only on the first "=" so values may contain "="
            if "=" not in line:
                continue

            key, _, value = line.partition("=")
            key   = key.strip().lower()
            value = value.strip()

            if key == _DAT_KEY_HARDENING_INDEX:
                try:
                    hardening_index = int(value)
                except ValueError:
                    hardening_index = 0

            elif key == _DAT_KEY_TESTS_PERFORMED:
                try:
                    tests_performed = int(value)
                except ValueError:
                    tests_performed = 0

            elif key == _DAT_KEY_LYNIS_VERSION:
                lynis_version = value

            elif key == _DAT_KEY_WARNING:
                if value:
                    warnings.append(parse_finding(value))

            elif key == _DAT_KEY_SUGGESTION:
                if value:
                    suggestions.append(parse_finding(value))

    return {
        "hardening_index": hardening_index,
        "tests_performed": tests_performed,
        "lynis_version":   lynis_version,
        "warnings":        warnings,
        "suggestions":     suggestions,
    }


# ─── Diff ─────────────────────────────────────────────────────────────────────


def _extract_ids(findings: list) -> set:
    """Return the set of test_id values from a list of finding dicts."""
    return {f["test_id"] for f in findings if f.get("test_id")}


def compute_diff(pre: dict, post: dict) -> dict:
    """Compute the delta between a pre-hardening and post-hardening Lynis report.

    Uses set operations on test_id values to identify resolved and new findings.

    Args:
        pre:  Structured dict returned by :func:`parse_dat_file` for the
              pre-hardening scan.
        post: Structured dict returned by :func:`parse_dat_file` for the
              post-hardening scan.

    Returns:
        dict with the following keys:

        * ``hardening_index_delta``   – formatted string, e.g. ``"+12"`` or ``"-3"``
        * ``hardening_index_numeric`` – raw integer delta (post minus pre)
        * ``warnings_resolved``       – count of warning test_ids present in pre
          but absent in post
        * ``warnings_resolved_ids``   – sorted list of those test_ids
        * ``new_warnings``            – count of warning test_ids new in post
        * ``new_warnings_ids``        – sorted list of those test_ids
        * ``suggestions_resolved``    – analogous for suggestions
        * ``suggestions_resolved_ids``
        * ``new_suggestions``
        * ``new_suggestions_ids``
    """
    pre_idx  = pre.get("hardening_index", 0)
    post_idx = post.get("hardening_index", 0)
    numeric_delta = post_idx - pre_idx
    delta_str = f"+{numeric_delta}" if numeric_delta >= 0 else str(numeric_delta)

    pre_warn_ids  = _extract_ids(pre.get("warnings", []))
    post_warn_ids = _extract_ids(post.get("warnings", []))
    pre_sugg_ids  = _extract_ids(pre.get("suggestions", []))
    post_sugg_ids = _extract_ids(post.get("suggestions", []))

    warn_resolved     = sorted(pre_warn_ids - post_warn_ids)
    new_warns         = sorted(post_warn_ids - pre_warn_ids)
    sugg_resolved     = sorted(pre_sugg_ids - post_sugg_ids)
    new_suggs         = sorted(post_sugg_ids - pre_sugg_ids)

    return {
        "hardening_index_delta":    delta_str,
        "hardening_index_numeric":  numeric_delta,
        "warnings_resolved":        len(warn_resolved),
        "warnings_resolved_ids":    warn_resolved,
        "new_warnings":             len(new_warns),
        "new_warnings_ids":         new_warns,
        "suggestions_resolved":     len(sugg_resolved),
        "suggestions_resolved_ids": sugg_resolved,
        "new_suggestions":          len(new_suggs),
        "new_suggestions_ids":      new_suggs,
    }


# ─── Classification ───────────────────────────────────────────────────────────


def _load_whitelist(auto_remediate_path: str) -> set:
    """Parse test IDs from an ``auto-remediate.conf`` file.

    Each non-comment, non-blank line is expected to be pipe-delimited with the
    test ID as the first field (possibly with trailing whitespace).

    Args:
        auto_remediate_path: Path to the conf file.

    Returns:
        Set of upper-cased test ID strings.  Returns an empty set if the file
        does not exist or cannot be read.
    """
    path = Path(auto_remediate_path)
    if not path.exists():
        return set()

    whitelist: set = set()
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            # First field before the first "|" is the test ID
            test_id = line.split("|")[0].strip().upper()
            if test_id:
                whitelist.add(test_id)

    return whitelist


def classify_findings(findings: list, auto_remediate_path: str | None) -> dict:
    """Classify a list of findings into three buckets.

    Classification rules (applied in order):

    1. If ``test_id`` is in the auto-remediate whitelist  → ``safe_to_remediate``
    2. If ``description`` matches environment patterns (USB, physical, BIOS,
       bootloader, grub, partition, encrypt, LUKS)           → ``not_applicable``
    3. Otherwise                                              → ``needs_human_review``

    Args:
        findings:             List of finding dicts (from :func:`parse_dat_file`).
        auto_remediate_path:  Path to ``auto-remediate.conf``, or ``None`` to
                              skip whitelist loading.

    Returns:
        dict with keys ``safe_to_remediate``, ``not_applicable``,
        ``needs_human_review`` — each containing a list of finding dicts.
    """
    whitelist: set = set()
    if auto_remediate_path is not None:
        whitelist = _load_whitelist(auto_remediate_path)

    safe_to_remediate = []
    not_applicable    = []
    needs_human_review = []

    for finding in findings:
        test_id     = finding.get("test_id", "").upper()
        description = finding.get("description", "")

        if test_id in whitelist:
            safe_to_remediate.append(finding)
        elif NOT_APPLICABLE_PATTERNS.search(description):
            not_applicable.append(finding)
        else:
            needs_human_review.append(finding)

    return {
        "safe_to_remediate":   safe_to_remediate,
        "not_applicable":      not_applicable,
        "needs_human_review":  needs_human_review,
    }


# ─── Summary builder ──────────────────────────────────────────────────────────


def build_summary(
    pre: dict,
    post: dict,
    distro: str,
    auto_remediate_path: str | None,
) -> dict:
    """Build a full comparison summary between pre- and post-hardening scans.

    Args:
        pre:                  Output of :func:`parse_dat_file` for pre-scan.
        post:                 Output of :func:`parse_dat_file` for post-scan.
        distro:               Distribution string, e.g. ``"ubuntu"`` or ``"unknown"``.
        auto_remediate_path:  Path to ``auto-remediate.conf``, or ``None``.

    Returns:
        Nested dict containing timestamp, distro, version info, pre/post metrics,
        delta, remaining findings, and classification results.
    """
    delta = compute_diff(pre, post)

    # Remaining findings in post (unresolved)
    post_warn_ids = _extract_ids(post.get("warnings", []))
    post_sugg_ids = _extract_ids(post.get("suggestions", []))

    remaining_warnings    = [w for w in post.get("warnings", [])
                              if w.get("test_id") in post_warn_ids]
    remaining_suggestions = [s for s in post.get("suggestions", [])
                              if s.get("test_id") in post_sugg_ids]

    warn_classification = classify_findings(remaining_warnings, auto_remediate_path)
    sugg_classification = classify_findings(remaining_suggestions, auto_remediate_path)

    return {
        "timestamp":     datetime.now(tz=timezone.utc).isoformat(),
        "distro":        distro,
        "lynis_version": post.get("lynis_version") or pre.get("lynis_version", ""),
        "pre": {
            "hardening_index": pre.get("hardening_index", 0),
            "tests_performed": pre.get("tests_performed", 0),
            "warnings_count":  len(pre.get("warnings", [])),
            "suggestions_count": len(pre.get("suggestions", [])),
        },
        "post": {
            "hardening_index": post.get("hardening_index", 0),
            "tests_performed": post.get("tests_performed", 0),
            "warnings_count":  len(post.get("warnings", [])),
            "suggestions_count": len(post.get("suggestions", [])),
        },
        "delta": delta,
        "remaining": {
            "warnings": {
                "count":    len(remaining_warnings),
                "findings": remaining_warnings,
            },
            "suggestions": {
                "count":    len(remaining_suggestions),
                "findings": remaining_suggestions,
            },
        },
        "classification": {
            "warnings":    warn_classification,
            "suggestions": sugg_classification,
        },
    }


# ─── CLI ──────────────────────────────────────────────────────────────────────


def _write_json(data: dict, output_path: str) -> None:
    """Write *data* as indented JSON to *output_path*.

    Args:
        data:        Serialisable dict.
        output_path: Destination file path.

    Raises:
        OSError: If the file cannot be written.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)
        fh.write("\n")


def _usage() -> None:
    print(
        "Usage:\n"
        "  lynis_parser.py <pre_dat> <post_dat> <output_json> [distro] [auto_remediate_conf]\n"
        "  lynis_parser.py --single <dat_file> <output_json>",
        file=sys.stderr,
    )


def main(argv: list[str] | None = None) -> int:
    """Entry point for the CLI.

    Returns:
        Exit code: 0 on success, 1 on error.
    """
    args = argv if argv is not None else sys.argv[1:]

    if not args:
        _usage()
        return 1

    # ── Single-file mode ──────────────────────────────────────────────────────
    if args[0] == "--single":
        if len(args) < 3:
            print("error: --single requires <dat_file> <output_json>", file=sys.stderr)
            _usage()
            return 1

        dat_file    = args[1]
        output_json = args[2]

        try:
            parsed = parse_dat_file(dat_file)
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

        result = {
            "timestamp":       datetime.now(tz=timezone.utc).isoformat(),
            "source_file":     dat_file,
            "hardening_index": parsed["hardening_index"],
            "tests_performed": parsed["tests_performed"],
            "lynis_version":   parsed["lynis_version"],
            "warnings":        parsed["warnings"],
            "suggestions":     parsed["suggestions"],
        }

        try:
            _write_json(result, output_json)
        except OSError as exc:
            print(f"error: could not write output: {exc}", file=sys.stderr)
            return 1

        print(f"hardening_index: {parsed['hardening_index']}")
        return 0

    # ── Comparison mode ───────────────────────────────────────────────────────
    if len(args) < 3:
        _usage()
        return 1

    pre_dat             = args[0]
    post_dat            = args[1]
    output_json         = args[2]
    distro              = args[3] if len(args) > 3 else "unknown"
    auto_remediate_conf = args[4] if len(args) > 4 else None

    try:
        pre  = parse_dat_file(pre_dat)
        post = parse_dat_file(post_dat)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    summary = build_summary(pre, post, distro, auto_remediate_conf)

    try:
        _write_json(summary, output_json)
    except OSError as exc:
        print(f"error: could not write output: {exc}", file=sys.stderr)
        return 1

    delta = summary["delta"]
    print(
        f"score delta: {delta['hardening_index_delta']} "
        f"({delta['warnings_resolved']} warnings resolved, "
        f"{delta['suggestions_resolved']} suggestions resolved)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
