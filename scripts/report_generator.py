#!/usr/bin/env python3
"""
report_generator.py — Generate human-readable and aggregate reports from
Linux-Hardener Lynis summary JSON files.

Usage:
    report_generator.py <summary_json> <output_dir>
    report_generator.py --aggregate <artifacts_dir> <output_dir>
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


def _bullet(text: str, indent: int = 2) -> str:
    prefix = " " * indent + "• "
    wrap_width = BOX_WIDTH - indent - 2
    words = text.split()
    lines = []
    current = prefix
    continuation = " " * (indent + 2)
    for word in words:
        if len(current) + len(word) + 1 > wrap_width + len(prefix):
            lines.append(current)
            current = continuation + word
        else:
            current = current + (" " if current != prefix else "") + word
    lines.append(current)
    return "\n".join(lines)


def _sign(n: int | float) -> str:
    return f"+{n}" if n > 0 else str(n)


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
    # Format timestamp for display
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
    raw_delta = delta.get("hardening_index", "N/A")
    # Normalise delta to a display string
    if isinstance(raw_delta, (int, float)):
        score_delta_str = _sign(raw_delta)
    else:
        score_delta_str = str(raw_delta)

    lines.append(_section_header("SCORE"))
    lines.append(f"  Before : {pre_score}")
    lines.append(f"  After  : {post_score}")
    lines.append(f"  Delta  : {score_delta_str}")

    # ------------------------------------------------------------------
    # Warnings
    # ------------------------------------------------------------------
    pre_warn = pre.get("warnings", "N/A")
    post_warn = post.get("warnings", "N/A")
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
    pre_sugg = pre.get("suggestions", "N/A")
    post_sugg = post.get("suggestions", "N/A")
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
    classification = summary.get("classification", {})
    safe_list = classification.get("safe_to_remediate", [])
    review_list = classification.get("needs_human_review", [])
    na_list = classification.get("not_applicable", [])

    lines.append(_section_header("REMAINING CLASSIFICATION"))

    # Warnings
    remaining_warnings = summary.get("remaining", {}).get("warnings", [])
    remaining_suggestions = summary.get("remaining", {}).get("suggestions", [])

    for category_label, items in [
        ("Warnings", remaining_warnings),
        ("Suggestions", remaining_suggestions),
    ]:
        if not items:
            continue
        lines.append(f"\n  {category_label}:")

        # Group by classification
        safe_items = [i for i in items if _classify_item(i, safe_list, review_list, na_list) == "safe"]
        review_items = [i for i in items if _classify_item(i, safe_list, review_list, na_list) == "review"]
        na_items = [i for i in items if _classify_item(i, safe_list, review_list, na_list) == "na"]
        unclassified = [
            i for i in items
            if _classify_item(i, safe_list, review_list, na_list) == "unclassified"
        ]

        lines.append(f"    Safe to remediate    : {len(safe_items)}")
        lines.append(f"    Needs human review   : {len(review_items)}")
        if review_items:
            for item in review_items:
                item_id = _item_id(item)
                lines.append(f"      - {item_id}")
        lines.append(f"    Not applicable       : {len(na_items)}")
        if na_items:
            for item in na_items:
                item_id = _item_id(item)
                lines.append(f"      - {item_id}")
        if unclassified:
            lines.append(f"    Unclassified         : {len(unclassified)}")
            for item in unclassified:
                item_id = _item_id(item)
                lines.append(f"      - {item_id}")

    # Summary counts from top-level classification keys
    lines.append(f"\n  Overall classification totals:")
    lines.append(f"    Safe to remediate  : {len(safe_list)}")
    lines.append(f"    Needs human review : {len(review_list)}")
    if review_list:
        for entry in review_list:
            lines.append(f"      - {_item_id(entry)}")
    lines.append(f"    Not applicable     : {len(na_list)}")
    if na_list:
        for entry in na_list:
            lines.append(f"      - {_item_id(entry)}")

    # ------------------------------------------------------------------
    # Known trade-offs
    # ------------------------------------------------------------------
    lines.append(_section_header("KNOWN TRADE-OFFS"))
    for title, description in KNOWN_TRADE_OFFS:
        lines.append(f"\n  [{title}]")
        lines.append(_bullet(description, indent=4))

    # ------------------------------------------------------------------
    # Intentionally not remediated
    # ------------------------------------------------------------------
    lines.append(_section_header("INTENTIONALLY NOT REMEDIATED"))
    for title, reason in INTENTIONALLY_NOT_REMEDIATED:
        lines.append(f"\n  [{title}]")
        lines.append(_bullet(reason, indent=4))

    # ------------------------------------------------------------------
    # Manual follow-up recommendations
    # ------------------------------------------------------------------
    lines.append(_section_header("MANUAL FOLLOW-UP RECOMMENDATIONS"))
    for i, rec in enumerate(MANUAL_FOLLOW_UP, start=1):
        lines.append("")
        # Wrap long recommendations
        prefix = f"  {i}. "
        continuation = " " * len(prefix)
        words = rec.split()
        current = prefix
        wrap_at = BOX_WIDTH - 2
        rec_lines = []
        for word in words:
            if len(current) + len(word) + 1 > wrap_at:
                rec_lines.append(current)
                current = continuation + word
            else:
                current = current + (" " if current != prefix else "") + word
        rec_lines.append(current)
        lines.extend(rec_lines)

    lines.append("")
    lines.append("═" * (BOX_WIDTH + 2))
    lines.append(f"  Report generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
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
# Classification helpers
# ---------------------------------------------------------------------------


def _item_id(item: dict | str) -> str:
    """Return a display identifier for a finding item."""
    if isinstance(item, dict):
        return item.get("test_id") or item.get("id") or item.get("description") or str(item)
    return str(item)


def _classify_item(
    item: dict | str,
    safe_list: list,
    review_list: list,
    na_list: list,
) -> str:
    """Return 'safe', 'review', 'na', or 'unclassified'."""
    item_id = _item_id(item)
    if any(_item_id(e) == item_id for e in safe_list):
        return "safe"
    if any(_item_id(e) == item_id for e in review_list):
        return "review"
    if any(_item_id(e) == item_id for e in na_list):
        return "na"
    return "unclassified"


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

    # Collect all summary.json files
    summary_files = sorted(artifacts_path.glob("*/summary.json"))
    if not summary_files:
        print(f"WARNING: no summary.json files found under {artifacts_dir}", file=sys.stderr)

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
        raw_delta = delta.get("hardening_index")

        # Compute numeric delta if not present or is a string like "+29"
        if isinstance(raw_delta, str):
            try:
                numeric_delta = int(raw_delta.lstrip("+"))
            except ValueError:
                numeric_delta = None
        elif isinstance(raw_delta, (int, float)):
            numeric_delta = int(raw_delta)
        else:
            numeric_delta = (
                (post_score - pre_score)
                if isinstance(pre_score, (int, float)) and isinstance(post_score, (int, float))
                else None
            )

        distro_results.append(
            {
                "distro": summary.get("distro", summary_file.parent.name),
                "lynis_version": summary.get("lynis_version", "unknown"),
                "timestamp": summary.get("timestamp", ""),
                "pre_score": pre_score,
                "post_score": post_score,
                "delta": numeric_delta,
                "pre_warnings": pre.get("warnings"),
                "post_warnings": post.get("warnings"),
                "pre_suggestions": pre.get("suggestions"),
                "post_suggestions": post.get("suggestions"),
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

    # ------------------------------------------------------------------
    # Print formatted table
    # ------------------------------------------------------------------
    _print_aggregate_table(distro_results)


def _print_aggregate_table(results: list[dict]) -> None:
    """Print a formatted summary table to stdout."""
    col_widths = {
        "distro": max(12, max((len(r["distro"]) for r in results), default=12)),
        "lynis": 7,
        "pre": 5,
        "post": 5,
        "delta": 6,
        "pre_w": 6,
        "post_w": 6,
        "pre_s": 6,
        "post_s": 6,
    }

    def row(*cells: tuple[str, str]) -> str:
        return "  ".join(str(v).ljust(w) for v, w in cells)

    header = row(
        ("DISTRO", col_widths["distro"]),
        ("LYNIS", col_widths["lynis"]),
        ("SCORE↑", col_widths["pre"]),
        ("SCORE↓", col_widths["post"]),
        ("DELTA", col_widths["delta"]),
        ("WARN↑", col_widths["pre_w"]),
        ("WARN↓", col_widths["post_w"]),
        ("SUGG↑", col_widths["pre_s"]),
        ("SUGG↓", col_widths["post_s"]),
    )

    sep = "─" * len(header)

    print()
    print("  CROSS-DISTRO AGGREGATE SUMMARY")
    print(f"  {sep}")
    print(f"  {header}")
    print(f"  {sep}")

    for r in results:
        delta_str = _sign(r["delta"]) if r["delta"] is not None else "N/A"
        data_row = row(
            (r["distro"], col_widths["distro"]),
            (r["lynis_version"], col_widths["lynis"]),
            (_na(r["pre_score"]), col_widths["pre"]),
            (_na(r["post_score"]), col_widths["post"]),
            (delta_str, col_widths["delta"]),
            (_na(r["pre_warnings"]), col_widths["pre_w"]),
            (_na(r["post_warnings"]), col_widths["post_w"]),
            (_na(r["pre_suggestions"]), col_widths["pre_s"]),
            (_na(r["post_suggestions"]), col_widths["post_s"]),
        )
        print(f"  {data_row}")

    print(f"  {sep}")

    # Averages (numeric only)
    def _avg(key: str) -> str:
        vals = [r[key] for r in results if isinstance(r[key], (int, float))]
        return f"{sum(vals) / len(vals):.1f}" if vals else "N/A"

    avg_row = row(
        ("AVG", col_widths["distro"]),
        ("", col_widths["lynis"]),
        (_avg("pre_score"), col_widths["pre"]),
        (_avg("post_score"), col_widths["post"]),
        (_avg("delta"), col_widths["delta"]),
        (_avg("pre_warnings"), col_widths["pre_w"]),
        (_avg("post_warnings"), col_widths["post_w"]),
        (_avg("pre_suggestions"), col_widths["pre_s"]),
        (_avg("post_suggestions"), col_widths["post_s"]),
    )
    print(f"  {avg_row}")
    print(f"  {sep}")
    print()
    print("  Column key: ↑ = before hardening, ↓ = after hardening")
    print()


def _na(value) -> str:
    return str(value) if value is not None else "N/A"


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
            print("ERROR: --aggregate requires <artifacts_dir> <output_dir>", file=sys.stderr)
            _usage()
            return 2
        artifacts_dir = args[1]
        output_dir = args[2]
        generate_aggregate(artifacts_dir, output_dir)
        return 0

    # Default: generate text report
    if len(args) < 2:
        print("ERROR: expected <summary_json> <output_dir>", file=sys.stderr)
        _usage()
        return 2

    summary_json_path = args[0]
    output_dir = args[1]

    # Validate and load summary JSON
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

    # Determine output file path
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
