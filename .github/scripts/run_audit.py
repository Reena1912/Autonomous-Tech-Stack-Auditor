"""
run_audit.py
------------
Entrypoint called by the GitHub Actions workflow.

Wires together dependency_reader → intelligence → report
and writes both audit_report.md and audit_results.json.

Usage:
    python run_audit.py \
        --repo-path /path/to/repo \
        --output audit_report.md \
        --json-output audit_results.json
"""

import argparse
import json
import sys
from pathlib import Path

from dependency_reader import parse_requirements_txt, parse_pyproject_toml
from intelligence import audit_packages
from report import generate_markdown_report


def main():
    parser = argparse.ArgumentParser(description="Tech Stack Auditor")
    parser.add_argument("--repo-path",    default=".",             help="Root of the repo to scan")
    parser.add_argument("--output",       default="audit_report.md", help="Markdown report output path")
    parser.add_argument("--json-output",  default="audit_results.json", help="JSON results output path")
    args = parser.parse_args()

    repo = Path(args.repo_path).resolve()
    packages: dict[str, str] = {}

    # Collect dependencies from whatever files exist 
    req_file     = repo / "requirements.txt"
    pyproject    = repo / "pyproject.toml"

    if req_file.exists():
        found = parse_requirements_txt(req_file)
        packages.update(found)
        print(f"[reader] requirements.txt → {len(found)} packages")

    if pyproject.exists():
        found = parse_pyproject_toml(pyproject)
        packages.update(found)
        print(f"[reader] pyproject.toml   → {len(found)} packages")

    if not packages:
        print("[!] No dependency files found. Nothing to audit.")
        sys.exit(0)

    # Collect dependencies from whatever files exist 
    results = audit_packages(packages)

    # Write JSON results (used by workflow steps for output vars) 
    json_path = Path(args.json_output)
    json_path.write_text(
        json.dumps({"results": results}, indent=2),
        encoding="utf-8"
    )
    print(f"\n[output] JSON results → {json_path}")

    # Write Markdown report 
    md_path = Path(args.output)
    generate_markdown_report(
        results,
        repo_path=str(repo),
        output_file=md_path,
    )
    print(f"[output] Markdown report → {md_path}")

    #  Exit code reflects security gate 
    # The workflow handles the actual gate, but we print a summary
    critical = sum(1 for r in results if r["risk"] == "critical")
    high     = sum(1 for r in results if r["risk"] == "high")

    print(f"\n{'='*50}")
    print(f"  Critical: {critical}  |  High: {high}  |  Total: {len(results)}")
    print(f"{'='*50}\n")


if __name__ == "__main__":
    main()