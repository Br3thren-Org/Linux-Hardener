#!/usr/bin/env python3
"""
report_generator.py — Generate human-readable and aggregate reports from
Linux-Hardener Lynis summary JSON files.

Usage:
    report_generator.py <summary_json> <output_dir>
    report_generator.py --aggregate <artifacts_dir> <output_dir>

Summary JSON schema (produced by lynis_parser.py):
    {
      "timestamp":     "<ISO-8601>",
      "distro":        "<distro-string>",
      "lynis_version": "<version>",
      "pre": {
        "hardening_index":    <int>,
        "tests_performed":    <int>,
        "warnings_count":     <int>,
        "suggestions_count":  <int>
      },
      "post": { ...same keys... },
      "delta": {
        "hardening_index_delta":    "<+N or -N>",
        "hardening_index_numeric":  <int>,
        "warnings_resolved":        <int>,
        "warnings_resolved_ids":    [...],
        "new_warnings":             <int>,
        "new_warnings_ids":         [...],
        "suggestions_resolved":     <int>,
        "suggestions_resolved_ids": [...],
        "new_suggestions":          <int>,
        "new_suggestions_ids":      [...]
      },
      "remaining": {
        "warnings":     { "count": <int>, "findings": [...] },
        "suggestions":  { "count": <int>, "findings": [...] }
      },
      "classification": {
        "warnings":    { "safe_to_remediate": [...], "not_applicable": [...], "needs_human_review": [...] },
        "suggestions": { "safe_to_remediate": [...], "not_applicable": [...], "needs_human_review": [...] }
      }
    }
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KNOWN_TRADE_OFFS = [
    (
        "AllowTcpForwarding disabled",
        "Breaks SSH tunneling workflows (e.g. database port-forwarding). "
        "Re-enable with AllowTcpForwarding yes in the hardening drop-in if tunneling is required.",
    ),
    (
        "/tmp mounted noexec",
        "Some package post-install scripts and build tools require execute "
        "permission on /tmp. dpkg/rpm hooks remount exec during package installs, "
        "but custom scripts may fail. Test before applying to build servers.",
    ),
    (
        "auditd enabled",
        "Minimal CPU and I/O overhead from audit rule processing. Log rotation "
        "is capped, but on high-throughput systems review the ruleset and consider "
        "rate-limiting audit events.",
    ),
    (
        "Unattended security upgrades",
        "Packages are updated automatically. A security patch could in rare cases "
        "change behaviour or restart a service. Auto-reboot is disabled by default; "
        "kernel patches require a manual reboot to take effect.",
    ),
]

INTENTIONALLY_NOT_REMEDIATED = [
    (
        "Separate partitions for /var, /var/log, /home",
        "Requires re-provisioning. Hetzner cloud images use a single root partition; "
        "repartitioning is not feasible post-provision without data loss.",
    ),
    (
        "Full disk encryption (LUKS)",
        "Requires console access to enter the passphrase on every boot. "
        "Incompatible with fully automated cloud reboots and Hetzner's provisioning model.",
    ),
    (
        "AppArmor enforcing mode (Debian/Ubuntu)",
        "Requires per-service AppArmor profiles. Enabling enforcing mode without "
        "profiles for every installed service risks breaking running services.",
    ),
    (
        "Kernel module signing",
        "Requires a custom-built kernel with the signing key embedded. "
        "Not feasible on stock distribution kernels.",
    ),
    (
        "Bootloader password",
        "Breaks Hetzner's cloud console and prevents automated reboots. "
        "Physical security of the boot process is the cloud provider's responsibility.",
    ),
]

MANUAL_FOLLOW_UP = [
    "Review remaining 'needs_human_review' findings above and remediate where applicable.",
    "Consider installing rkhunter or chkrootkit for additional rootkit detection.",
    "Validate AIDE database integrity after the first scheduled daily check.",
    "Review fail2ban jail status after 24 hours of production traffic.",
    "Confirm time synchronisation is stable: run 'chronyc tracking' or "
    "'timedatectl show --property=NTPSynchronized'.",
    "If AppArmor profiles exist for your workload, enable enforcing mode manually.",
    "Rotate SSH host keys if this image will be used as a snapshot/template.",
    "Schedule a periodic re-run of this hardening framework to catch configuration drift.",
]

BOX_WIDTH = 78  # inner width (between the border characters)


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


def _box_top(title: str) -> str:
    """Return a top border line with the title centred."""
    inner = BOX_WIDTH
    title_str = f"  {title}  "
    pad = inner - len(title_str)
    left = pad // 2
    right = pad - left
    return "╔" + "═" * left + title_str + "═" * right + "╗"


def _box_bottom() -> str:
    return "╚" + "═" * BOX_WIDTH + "╝"


def _box_line(text: str = "") -> str:
    """Return a single content line padded to BOX_WIDTH."""
    padded = f" {text}"
    return "║" + padded.ljust(BOX_WIDTH) + "║"


def _section_header(title: str) -> str:
    bar = "─" * BOX_WIDTH
    return f"\n{bar}\n  {title}\n{bar}"


def _wrap_text(text: str, indent: int, total_width: int) -> list[str]:
    """Word-wrap *text* to fit within *total_width*, indented by *indent* spaces."""
    prefix = " " * indent
    max_line = total_width - indent
    words = text.split()
    lines = []
    current = ""
    for word in words:
        if not current:
            current = word
        elif len(current) + 1 + len(word) <= max_line:
            current += " " + word
        else:
            lines.append(prefix + current)
            current = word
    if current:
        lines.append(prefix + current)
    return lines


def _sign(n: int | float) -> str:
    return f"+{n}" if n > 0 else str(n)


def _na(value) -> str:
    return str(value) if value is not None else "N/A"


def _item_id(item: dict | str) -> str:
    """Return a short display identifier for a finding item."""
    if isinstance(item, dict):
        tid = item.get("test_id", "")
        desc = item.get("description", "")
        if tid and desc:
            return f"{tid}: {desc}"
        return tid or desc or str(item)
    return str(item)


# ---------------------------------------------------------------------------
# generate_text_report
# ---------------------------------------------------------------------------


def generate_text_report(summary: dict, output_path: str) -> None:
    """Write a human-readable text report to *output_path*.

    Parameters
    ----------
    summary:
        Parsed contents of a summary.json file produced by lynis_parser.py.
    output_path:
        Destination file path (parent directory must exist).
    """
    lines: list[str] = []

    # ------------------------------------------------------------------
    # Header box
    # ------------------------------------------------------------------
    distro = summary.get("distro", "unknown")
    lynis_version = summary.get("lynis_version", "unknown")
    timestamp = summary.get("timestamp", datetime.now(timezone.utc).isoformat())
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        date_str = dt.strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, AttributeError):
        date_str = str(timestamp)

    lines.append(_box_top("LINUX HARDENER — AUDIT REPORT"))
    lines.append(_box_line())
    lines.append(_box_line(f"Distribution  : {distro}"))
    lines.append(_box_line(f"Date          : {date_str}"))
    lines.append(_box_line(f"Lynis version : {lynis_version}"))
    lines.append(_box_line())
    lines.append(_box_bottom())

    # ------------------------------------------------------------------
    # Score
    # ------------------------------------------------------------------
    pre = summary.get("pre", {})
    post = summary.get("post", {})
    delta = summary.get("delta", {})

    pre_score = pre.get("hardening_index", "N/A")
    post_score = post.get("hardening_index", "N/A")
    numeric_delta = delta.get("hardening_index_numeric")
    score_delta_str = delta.get("hardening_index_delta", "N/A")
    if numeric_delta is not None and score_delta_str == "N/A":
        score_delta_str = _sign(numeric_delta)

    lines.append(_section_header("SCORE"))
    lines.append(f"  Before : {pre_score}")
    lines.append(f"  After  : {post_score}")
    lines.append(f"  Delta  : {score_delta_str}")

    # ------------------------------------------------------------------
    # Warnings
    # ------------------------------------------------------------------
    pre_warn = pre.get("warnings_count", "N/A")
    post_warn = post.get("warnings_count", "N/A")
    resolved_warn = delta.get("warnings_resolved", "N/A")
    new_warn = delta.get("new_warnings", "N/A")

    lines.append(_section_header("WARNINGS"))
    lines.append(f"  Before   : {pre_warn}")
    lines.append(f"  After    : {post_warn}")
    lines.append(f"  Resolved : {resolved_warn}")
    lines.append(f"  New      : {new_warn}")

    # ------------------------------------------------------------------
    # Suggestions
    # ------------------------------------------------------------------
    pre_sugg = pre.get("suggestions_count", "N/A")
    post_sugg = post.get("suggestions_count", "N/A")
    resolved_sugg = delta.get("suggestions_resolved", "N/A")
    new_sugg = delta.get("new_suggestions", "N/A")

    lines.append(_section_header("SUGGESTIONS"))
    lines.append(f"  Before   : {pre_sugg}")
    lines.append(f"  After    : {post_sugg}")
    lines.append(f"  Resolved : {resolved_sugg}")
    lines.append(f"  New      : {new_sugg}")

    # ------------------------------------------------------------------
    # Remaining classification
    # ------------------------------------------------------------------
    remaining = summary.get("remaining", {})
    classification = summary.get("classification", {})

    lines.append(_section_header("REMAINING CLASSIFICATION"))

    for category_key, category_label in [("warnings", "Warnings"), ("suggestions", "Suggestions")]:
        rem_block = remaining.get(category_key, {})
        findings = rem_block.get("findings", []) if isinstance(rem_block, dict) else []
        cls_block = classification.get(category_key, {})
        safe_items = cls_block.get("safe_to_remediate", [])
        review_items = cls_block.get("needs_human_review", [])
        na_items = cls_block.get("not_applicable", [])

        lines.append(f"\n  {category_label}:")
        lines.append(f"    Safe to remediate  : {len(safe_items)}")
        lines.append(f"    Needs human review : {len(review_items)}")
        if review_items:
            for item in review_items:
                lines.append(f"      - {_item_id(item)}")
        lines.append(f"    Not applicable     : {len(na_items)}")
        if na_items:
            for item in na_items:
                lines.append(f"      - {_item_id(item)}")

        # Any findings not yet classified (edge case: classification list may be
        # shorter than remaining findings if auto-remediate.conf is absent)
        classified_ids = set()
        for group in (safe_items, review_items, na_items):
            for item in group:
                classified_ids.add(_item_id(item))
        unclassified = [f for f in findings if _item_id(f) not in classified_ids]
        if unclassified:
            lines.append(f"    Unclassified       : {len(unclassified)}")
            for item in unclassified:
                lines.append(f"      - {_item_id(item)}")

    # ------------------------------------------------------------------
    # Known trade-offs
    # ------------------------------------------------------------------
    lines.append(_section_header("KNOWN TRADE-OFFS"))
    for title, description in KNOWN_TRADE_OFFS:
        lines.append(f"\n  [{title}]")
        for wrapped_line in _wrap_text(description, indent=4, total_width=BOX_WIDTH):
            lines.append(wrapped_line)

    # ------------------------------------------------------------------
    # Intentionally not remediated
    # ------------------------------------------------------------------
    lines.append(_section_header("INTENTIONALLY NOT REMEDIATED"))
    for title, reason in INTENTIONALLY_NOT_REMEDIATED:
        lines.append(f"\n  [{title}]")
        for wrapped_line in _wrap_text(reason, indent=4, total_width=BOX_WIDTH):
            lines.append(wrapped_line)

    # ------------------------------------------------------------------
    # Manual follow-up recommendations
    # ------------------------------------------------------------------
    lines.append(_section_header("MANUAL FOLLOW-UP RECOMMENDATIONS"))
    for i, rec in enumerate(MANUAL_FOLLOW_UP, start=1):
        lines.append("")
        prefix_len = len(f"  {i}. ")
        first_line_prefix = f"  {i}. "
        continuation_prefix = " " * prefix_len
        words = rec.split()
        rec_lines = []
        current_prefix = first_line_prefix
        current = ""
        for word in words:
            candidate = (current + " " + word).strip() if current else word
            if len(current_prefix) + len(candidate) <= BOX_WIDTH - 2:
                current = candidate
            else:
                rec_lines.append(current_prefix + current)
                current_prefix = continuation_prefix
                current = word
        if current:
            rec_lines.append(current_prefix + current)
        lines.extend(rec_lines)

    lines.append("")
    lines.append("═" * (BOX_WIDTH + 2))
    lines.append(
        f"  Report generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
    )
    lines.append("═" * (BOX_WIDTH + 2))
    lines.append("")

    # ------------------------------------------------------------------
    # Write output
    # ------------------------------------------------------------------
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(lines)
    output.write_text(content, encoding="utf-8")
    print(f"Report written to: {output_path}")


# ---------------------------------------------------------------------------
# generate_aggregate
# ---------------------------------------------------------------------------


def generate_aggregate(artifacts_dir: str, output_dir: str) -> None:
    """Scan *artifacts_dir* for */summary.json files, build aggregate report.

    Writes ``aggregate-summary.json`` to *output_dir* and prints a formatted
    table to stdout.

    Parameters
    ----------
    artifacts_dir:
        Root directory to scan for summary.json files (one level deep).
    output_dir:
        Directory where aggregate-summary.json will be written.
    """
    artifacts_path = Path(artifacts_dir)
    output_path = Path(output_dir)

    if not artifacts_path.is_dir():
        print(f"ERROR: artifacts directory not found: {artifacts_dir}", file=sys.stderr)
        sys.exit(1)

    summary_files = sorted(artifacts_path.glob("*/summary.json"))
    if not summary_files:
        print(
            f"WARNING: no summary.json files found under {artifacts_dir}",
            file=sys.stderr,
        )

    distro_results: list[dict] = []

    for summary_file in summary_files:
        try:
            raw = summary_file.read_text(encoding="utf-8")
            summary = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"WARNING: could not parse {summary_file}: {exc}", file=sys.stderr)
            continue

        pre = summary.get("pre", {})
        post = summary.get("post", {})
        delta = summary.get("delta", {})

        pre_score = pre.get("hardening_index")
        post_score = post.get("hardening_index")
        numeric_delta = delta.get("hardening_index_numeric")
        if numeric_delta is None:
            delta_str = delta.get("hardening_index_delta")
            if delta_str is not None:
                try:
                    numeric_delta = int(str(delta_str).lstrip("+"))
                except ValueError:
                    numeric_delta = None
        if numeric_delta is None and isinstance(pre_score, (int, float)) and isinstance(post_score, (int, float)):
            numeric_delta = post_score - pre_score

        distro_results.append(
            {
                "distro": summary.get("distro", summary_file.parent.name),
                "lynis_version": summary.get("lynis_version", "unknown"),
                "timestamp": summary.get("timestamp", ""),
                "pre_score": pre_score,
                "post_score": post_score,
                "delta": numeric_delta,
                "pre_warnings": pre.get("warnings_count"),
                "post_warnings": post.get("warnings_count"),
                "warnings_resolved": delta.get("warnings_resolved"),
                "new_warnings": delta.get("new_warnings"),
                "pre_suggestions": pre.get("suggestions_count"),
                "post_suggestions": post.get("suggestions_count"),
                "suggestions_resolved": delta.get("suggestions_resolved"),
                "new_suggestions": delta.get("new_suggestions"),
                "source_file": str(summary_file),
            }
        )

    # ------------------------------------------------------------------
    # Build aggregate JSON
    # ------------------------------------------------------------------
    aggregate = {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "distros_scanned": len(distro_results),
        "results": distro_results,
    }

    output_path.mkdir(parents=True, exist_ok=True)
    agg_file = output_path / "aggregate-summary.json"
    agg_file.write_text(json.dumps(aggregate, indent=2), encoding="utf-8")
    print(f"Aggregate summary written to: {agg_file}")

    _print_aggregate_table(distro_results)


def _print_aggregate_table(results: list[dict]) -> None:
    """Print a formatted summary table to stdout."""
    if not results:
        print("  (no results to display)")
        return

    col_w_distro = max(12, max(len(r["distro"]) for r in results))
    col_w_lynis = max(7, max(len(r.get("lynis_version", "N/A")) for r in results))

    COL_NUMERIC = 6

    def cell(v, w: int) -> str:
        return str(v).ljust(w)

    def header_row() -> str:
        return "  ".join([
            cell("DISTRO", col_w_distro),
            cell("LYNIS", col_w_lynis),
            cell("PRE", COL_NUMERIC),
            cell("POST", COL_NUMERIC),
            cell("DELTA", COL_NUMERIC),
            cell("W-PRE", COL_NUMERIC),
            cell("W-PST", COL_NUMERIC),
            cell("W-RES", COL_NUMERIC),
            cell("S-PRE", COL_NUMERIC),
            cell("S-PST", COL_NUMERIC),
            cell("S-RES", COL_NUMERIC),
        ])

    header = header_row()
    sep = "─" * len(header)

    print()
    print("  CROSS-DISTRO AGGREGATE SUMMARY")
    print(f"  {sep}")
    print(f"  {header}")
    print(f"  {sep}")

    for r in results:
        d_str = _sign(r["delta"]) if isinstance(r["delta"], (int, float)) else "N/A"
        data = "  ".join([
            cell(r["distro"], col_w_distro),
            cell(r.get("lynis_version", "N/A"), col_w_lynis),
            cell(_na(r["pre_score"]), COL_NUMERIC),
            cell(_na(r["post_score"]), COL_NUMERIC),
            cell(d_str, COL_NUMERIC),
            cell(_na(r["pre_warnings"]), COL_NUMERIC),
            cell(_na(r["post_warnings"]), COL_NUMERIC),
            cell(_na(r["warnings_resolved"]), COL_NUMERIC),
            cell(_na(r["pre_suggestions"]), COL_NUMERIC),
            cell(_na(r["post_suggestions"]), COL_NUMERIC),
            cell(_na(r["suggestions_resolved"]), COL_NUMERIC),
        ])
        print(f"  {data}")

    print(f"  {sep}")

    # Averages row (numeric fields only)
    def avg(key: str) -> str:
        vals = [r[key] for r in results if isinstance(r.get(key), (int, float))]
        return f"{sum(vals) / len(vals):.1f}" if vals else "N/A"

    avg_data = "  ".join([
        cell("AVG", col_w_distro),
        cell("", col_w_lynis),
        cell(avg("pre_score"), COL_NUMERIC),
        cell(avg("post_score"), COL_NUMERIC),
        cell(avg("delta"), COL_NUMERIC),
        cell(avg("pre_warnings"), COL_NUMERIC),
        cell(avg("post_warnings"), COL_NUMERIC),
        cell(avg("warnings_resolved"), COL_NUMERIC),
        cell(avg("pre_suggestions"), COL_NUMERIC),
        cell(avg("post_suggestions"), COL_NUMERIC),
        cell(avg("suggestions_resolved"), COL_NUMERIC),
    ])
    print(f"  {avg_data}")
    print(f"  {sep}")
    print()
    print("  Column key: PRE=before, POST=after, W=warnings, S=suggestions, RES=resolved")
    print()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _usage() -> None:
    print(__doc__.strip())


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]

    if not args or args[0] in ("-h", "--help"):
        _usage()
        return 0

    if args[0] == "--aggregate":
        if len(args) < 3:
            print(
                "ERROR: --aggregate requires <artifacts_dir> <output_dir>",
                file=sys.stderr,
            )
            _usage()
            return 2
        generate_aggregate(artifacts_dir=args[1], output_dir=args[2])
        return 0

    # Default: generate text report
    if len(args) < 2:
        print("ERROR: expected <summary_json> <output_dir>", file=sys.stderr)
        _usage()
        return 2

    summary_json_path = args[0]
    output_dir = args[1]

    summary_path = Path(summary_json_path)
    if not summary_path.exists():
        print(f"ERROR: summary JSON not found: {summary_json_path}", file=sys.stderr)
        return 1

    try:
        raw = summary_path.read_text(encoding="utf-8")
        summary = json.loads(raw)
    except OSError as exc:
        print(f"ERROR: could not read {summary_json_path}: {exc}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"ERROR: invalid JSON in {summary_json_path}: {exc}", file=sys.stderr)
        return 1

    if not isinstance(summary, dict):
        print(
            f"ERROR: expected a JSON object in {summary_json_path}, got {type(summary).__name__}",
            file=sys.stderr,
        )
        return 1

    output_dir_path = Path(output_dir)
    output_dir_path.mkdir(parents=True, exist_ok=True)

    distro = summary.get("distro", "report").replace("/", "-").replace(" ", "_")
    timestamp_tag = ""
    ts = summary.get("timestamp", "")
    if ts:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            timestamp_tag = "_" + dt.strftime("%Y%m%d_%H%M%S")
        except (ValueError, AttributeError):
            pass

    output_file = output_dir_path / f"report_{distro}{timestamp_tag}.txt"
    generate_text_report(summary, str(output_file))
    return 0


if __name__ == "__main__":
    sys.exit(main())
