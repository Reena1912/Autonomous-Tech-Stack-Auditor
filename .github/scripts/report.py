"""
auditor_reporter.py
-------------------
Phase 3: Report generator for the Tech Stack Auditor.

Consumes the structured results list from auditor_intelligence.py
and produces a clean, actionable Markdown report.
"""

from datetime import datetime, timezone
from pathlib import Path


#  Helpers 

RISK_EMOJI = {
    "critical":   "🔴",
    "high":       "🟠",
    "medium":     "🟡",
    "low-medium": "🟡",
    "low":        "🟢",
}

RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low-medium": 3, "low": 4}


def _badge(risk: str) -> str:
    return f"`{risk.upper()}`"


def _sort(results: list[dict]) -> list[dict]:
    return sorted(results, key=lambda r: RISK_ORDER.get(r["risk"], 5))


def _days_label(days: int | None) -> str:
    if days is None:
        return "unknown"
    if days < 30:
        return f"{days}d ago"
    if days < 365:
        return f"{days // 30}mo ago"
    return f"{days // 365}y {(days % 365) // 30}mo ago"


#  Section builders 

def _build_header(results: list[dict], repo_path: str) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total = len(results)
    critical = sum(1 for r in results if r["risk"] == "critical")
    high     = sum(1 for r in results if r["risk"] == "high")
    medium   = sum(1 for r in results if r["risk"] in ("medium", "low-medium"))
    low      = sum(1 for r in results if r["risk"] == "low")

    overall = "✅ Healthy"
    if critical:
        overall = "🚨 Critical — immediate action required"
    elif high:
        overall = "⚠️ At Risk — review recommended"
    elif medium:
        overall = "🔍 Attention needed"

    return f"""# 🔍 Tech Stack Audit Report

**Repo:** `{repo_path}`
**Scanned:** {now}
**Overall status:** {overall}

| 🔴 Critical | 🟠 High | 🟡 Medium | 🟢 Low | Total |
|:-----------:|:-------:|:---------:|:------:|:-----:|
| {critical} | {high} | {medium} | {low} | {total} |

---
"""


def _build_urgent(results: list[dict]) -> str:
    urgent = [r for r in results if r["risk"] in ("critical", "high")]
    if not urgent:
        return ""

    lines = ["##  Urgent — Action Required\n"]
    lines.append("> These packages have CVEs, are yanked, or are known-deprecated. "
                 "Do not ship without addressing these.\n")

    for r in _sort(urgent):
        icon = RISK_EMOJI[r["risk"]]
        lines.append(f"### {icon} `{r['package']}` — {_badge(r['risk'])}\n")

        if r["cves"]:
            lines.append(f"**{r['cve_count']} CVE(s) detected:**\n")
            for cve in r["cves"]:
                fix = ", ".join(cve["fix_versions"]) if cve["fix_versions"] else "no fix available yet"
                lines.append(f"- **{cve['id']}** → fix in `{fix}`")
                if cve.get("description"):
                    lines.append(f"  > {cve['description'][:180]}")
            lines.append("")

        if r["is_yanked"]:
            lines.append(f"- **Yanked on PyPI** — this release was pulled by the maintainer. "
                         f"Latest safe version: `{r['latest_version']}`\n")

        if r["is_deprecated"] and r["replacement"]:
            lines.append(f"- **Deprecated** — replace with `{r['replacement']}`\n")

        lines.append(f"**Current spec:** `{r['version_spec'] or 'unpinned'}`  "
                     f"**Latest:** `{r['latest_version']}`\n")
        lines.append("---\n")

    return "\n".join(lines)


def _build_warnings(results: list[dict]) -> str:
    warn = [r for r in results if r["risk"] in ("medium", "low-medium")]
    if not warn:
        return ""

    lines = ["## ⚠️ Warnings — Review Soon\n"]
    lines.append("> No CVEs found, but these packages are aging or stale. "
                 "Stale dependencies are a supply-chain risk vector.\n")
    lines.append("| Package | Spec | Latest | Last Updated | Status |")
    lines.append("|---------|------|--------|-------------|--------|")

    for r in _sort(warn):
        days_label = _days_label(r["last_updated_days"])
        status = "🕸️ Stale" if r["staleness"] == "stale" else "📅 Aging"
        lines.append(
            f"| `{r['package']}` | `{r['version_spec'] or 'unpinned'}` "
            f"| `{r['latest_version']}` | {days_label} | {status} |"
        )

    lines.append("")
    return "\n".join(lines)


def _build_healthy(results: list[dict]) -> str:
    healthy = [r for r in results if r["risk"] == "low"]
    if not healthy:
        return ""

    lines = ["## ✅ Healthy — No Action Needed\n"]
    lines.append("| Package | Spec | Latest | Last Updated |")
    lines.append("|---------|------|--------|-------------|")

    for r in sorted(healthy, key=lambda r: r["package"].lower()):
        days_label = _days_label(r["last_updated_days"])
        lines.append(
            f"| `{r['package']}` | `{r['version_spec'] or 'unpinned'}` "
            f"| `{r['latest_version']}` | {days_label} |"
        )

    lines.append("")
    return "\n".join(lines)


def _build_action_plan(results: list[dict]) -> str:
    actions = []

    for r in _sort(results):
        if r["cves"]:
            for cve in r["cves"]:
                fix = cve["fix_versions"][0] if cve["fix_versions"] else None
                if fix:
                    actions.append(
                        f"- [ ] **Upgrade `{r['package']}`** to `{fix}` "
                        f"to patch {cve['id']}"
                    )
                else:
                    actions.append(
                        f"- [ ] **Investigate `{r['package']}`** — {cve['id']} "
                        f"has no fix yet; consider alternatives"
                    )

        if r["is_deprecated"] and r["replacement"]:
            actions.append(
                f"- [ ] **Replace `{r['package']}`** with `{r['replacement']}`"
            )

        if r["is_yanked"]:
            actions.append(
                f"- [ ] **Unpin `{r['package']}`** — current release is yanked, "
                f"upgrade to `{r['latest_version']}`"
            )

        if r["staleness"] == "stale" and not r["cves"]:
            actions.append(
                f"- [ ] **Review `{r['package']}`** — no release in "
                f"{r['last_updated_days'] // 365}+ years; check for maintained fork"
            )

    if not actions:
        return "## 📋 Action Plan\n\n> Nothing to do — your stack looks clean! 🎉\n"

    return "## 📋 Action Plan\n\n" + "\n".join(actions) + "\n"


def _build_footer() -> str:
    return """---

*Generated by **Tech Stack Auditor** · Sources: PyPI JSON API, pip-audit (OSS vulnerability DB)*
*This report is a starting point — always verify CVE applicability to your specific usage.*
"""



def generate_markdown_report(
    results: list[dict],
    repo_path: str = ".",
    output_file: Path | None = None,
) -> str:
    """
    Generate a full Markdown audit report from intelligence results.

    Args:
        results:     Output of auditor_intelligence.audit_packages()
        repo_path:   Label for the repo being scanned (shown in header)
        output_file: If provided, write the report to this path

    Returns:
        The full Markdown string
    """
    sections = [
        _build_header(results, repo_path),
        _build_urgent(results),
        _build_warnings(results),
        _build_healthy(results),
        _build_action_plan(results),
        _build_footer(),
    ]

    report = "\n".join(s for s in sections if s)

    if output_file:
        output_file.write_text(report, encoding="utf-8")
        print(f"\n Report written to: {output_file}")

    return report


# CLI entry point 

if __name__ == "__main__":
    import sys
    from pathlib import Path
    from dependency_reader import parse_requirements_txt
    from intelligence import audit_packages

    req_file = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("requirements.txt")
    out_file = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("audit_report.md")

    if not req_file.exists():
        print(f"[ERROR] File not found: {req_file}")
        sys.exit(1)

    packages = parse_requirements_txt(req_file)
    results  = audit_packages(packages)
    report   = generate_markdown_report(
        results,
        repo_path=str(req_file.parent.resolve()),
        output_file=out_file,
    )

    print(report)