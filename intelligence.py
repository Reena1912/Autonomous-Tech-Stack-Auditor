"""
auditor_intelligence.py
-----------------------
Phase 2: Intelligence layer for the Tech Stack Auditor.

Given a list of package names, this module:
  1. Hits the PyPI JSON API to get latest version + last release date
  2. Runs pip-audit to surface CVEs and known vulnerabilities
  3. Cross-checks against a known-deprecated package registry
  4. Returns a structured report per package
"""

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import requests

# Constants 

PYPI_API = "https://pypi.org/pypi/{package}/json"
STALE_THRESHOLD_DAYS = 730  # 2 years without a release = stale signal

# Known deprecated packages with their recommended replacements
KNOWN_DEPRECATED: dict[str, str] = {
    "pycrypto":       "pycryptodome",
    "sha":            "hashlib (stdlib)",
    "md5":            "hashlib (stdlib)",
    "sklearn":        "scikit-learn",
    "BeautifulSoup":  "beautifulsoup4",
    "flask-script":   "flask CLI (built-in)",
    "python-dateutil":"dateutil is fine but check if datetime stdlib covers your need",
    "nose":           "pytest",
    "mock":           "unittest.mock (stdlib)",
    "simplejson":     "json (stdlib)",
    "unipath":        "pathlib (stdlib)",
    "futures":        "concurrent.futures (stdlib)",
    "functools32":    "functools (stdlib)",
    "pkg_resources":  "importlib.resources (stdlib)",
    "safety":         "pip-audit (Safety went commercial)",
}


# PyPI Metadata 

def fetch_pypi_metadata(package: str) -> dict:
    """Fetch package info from PyPI JSON API."""
    url = PYPI_API.format(package=package)
    try:
        resp = requests.get(url, timeout=8)
        if resp.status_code == 404:
            return {"error": "not_found_on_pypi"}
        resp.raise_for_status()
        data = resp.json()

        info = data.get("info", {})
        releases = data.get("releases", {})

        # Find the most recent release date across all versions
        latest_version = info.get("version", "unknown")
        latest_date = None

        for version, files in releases.items():
            for f in files:
                upload_time = f.get("upload_time_iso_8601") or f.get("upload_time")
                if upload_time:
                    try:
                        dt = datetime.fromisoformat(
                            upload_time.replace("Z", "+00:00")
                        )
                        if latest_date is None or dt > latest_date:
                            latest_date = dt
                    except ValueError:
                        pass

        days_since_update = None
        if latest_date:
            now = datetime.now(timezone.utc)
            days_since_update = (now - latest_date).days

        return {
            "latest_version":     latest_version,
            "last_updated_days":  days_since_update,
            "last_updated_date":  latest_date.strftime("%Y-%m-%d") if latest_date else "unknown",
            "is_yanked":          info.get("yanked", False),
            "summary":            info.get("summary", ""),
            "home_page":          info.get("home_page", ""),
        }

    except requests.RequestException as e:
        return {"error": str(e)}


# pip-audit CVE Scan 

def run_pip_audit(packages: dict[str, str]) -> dict[str, list[dict]]:
    """
    Run pip-audit against a dict of package -> version spec.
    Returns a dict: { package_name: [ {id, fix_versions, description}, ... ] }
    """
    # Build requirement lines like:
    # requests==2.31.0
    # numpy>=1.24
    req_lines = [
        f"{pkg}{spec}" if spec else pkg
        for pkg, spec in packages.items()
    ]

    req_content = "\n".join(req_lines)

    with tempfile.NamedTemporaryFile(
        mode="w",
        delete=False,
        suffix=".txt"
    ) as tmp:
        tmp.write(req_content)
        tmp_req = Path(tmp.name)

    result = subprocess.run(
        [
            sys.executable, "-m", "pip_audit",
            "--requirement", str(tmp_req),
            "--format", "json",
            "--progress-spinner", "off",
            "--skip-editable",
        ],
        capture_output=True,
        text=True,
    )

    vulnerabilities: dict[str, list[dict]] = {}

    output = result.stdout.strip()
    if not output:
        return vulnerabilities

    try:
        audit_data = json.loads(output)
    except json.JSONDecodeError:
        return vulnerabilities

    for dep in audit_data.get("dependencies", []):
        pkg_name = dep.get("name", "").lower()
        vulns = dep.get("vulns", [])
        if vulns:
            vulnerabilities[pkg_name] = [
                {
                    "id": v.get("id", ""),
                    "aliases": v.get("aliases", []),
                    "fix_versions": v.get("fix_versions", []),
                    "description": v.get("description", "")[:200],
                }
                for v in vulns
            ]

    return vulnerabilities


# Staleness & Deprecation Signals 

def classify_staleness(days: int | None) -> str:
    if days is None:
        return "unknown"
    if days > STALE_THRESHOLD_DAYS:
        return "stale"
    if days > 365:
        return "aging"
    return "active"


# Main Audit Runner 

def audit_packages(packages: dict[str, str]) -> list[dict]:
    """
    Full intelligence pass on a dict of package -> version spec.
    Returns a list of structured result dicts, one per package.
    """
    print(f"\n Running intelligence scan on {len(packages)} packages...\n")

    print("  [1/3] Running pip-audit for CVEs...")
    cve_map = run_pip_audit(packages)
    print(f"        Done. {len(cve_map)} package(s) with known vulnerabilities.\n")

    results = []

    for i, (pkg, version_spec) in enumerate(packages.items(), 1):
        print(f"  [2/3] PyPI metadata  ({i}/{len(packages)})  {pkg}")

        pypi = fetch_pypi_metadata(pkg)
        cves = cve_map.get(pkg.lower(), [])
        deprecated_replacement = KNOWN_DEPRECATED.get(pkg.lower())
        is_deprecated = pkg.lower() in KNOWN_DEPRECATED

        staleness = classify_staleness(pypi.get("last_updated_days"))

        risk = "low"
        if cves:
            risk = "critical"
        elif pypi.get("is_yanked"):
            risk = "high"
        elif is_deprecated:
            risk = "high"
        elif staleness == "stale":
            risk = "medium"
        elif staleness == "aging":
            risk = "low-medium"

        results.append({
            "package": pkg,
            "version_spec": version_spec,
            "risk": risk,
            "latest_version": pypi.get("latest_version", "unknown"),
            "last_updated_date": pypi.get("last_updated_date", "unknown"),
            "last_updated_days": pypi.get("last_updated_days"),
            "staleness": staleness,
            "is_yanked": pypi.get("is_yanked", False),
            "is_deprecated": is_deprecated,
            "replacement": deprecated_replacement,
            "cves": cves,
            "cve_count": len(cves),
            "pypi_error": pypi.get("error"),
        })

    return results


#  Pretty Printer for the final report

RISK_ICONS = {
    "critical":   "🔴",
    "high":       "🟠",
    "medium":     "🟡",
    "low-medium": "🟡",
    "low":        "🟢",
}

def print_report(results: list[dict]) -> None:
    print("\n" + "=" * 60)
    print("  AUDIT INTELLIGENCE REPORT")
    print("=" * 60)

    # Sort by risk severity
    risk_order = {"critical": 0, "high": 1, "medium": 2, "low-medium": 3, "low": 4}
    results_sorted = sorted(results, key=lambda r: risk_order.get(r["risk"], 5))

    for r in results_sorted:
        icon = RISK_ICONS.get(r["risk"], "⚪")
        print(f"\n{icon}  {r['package']}  [{r['risk'].upper()}]")
        print(f"   Installed spec : {r['version_spec'] or 'none'}")
        print(f"   Latest version : {r['latest_version']}")
        print(f"   Last updated   : {r['last_updated_date']}  ({r['last_updated_days'] or '?'} days ago)")
        print(f"   Staleness      : {r['staleness']}")

        if r["is_yanked"]:
            print("   ⚠️  YANKED on PyPI — do not use this version")

        if r["is_deprecated"]:
            replacement = r["replacement"] or "no direct replacement listed"
            print(f"   ⚠️  DEPRECATED — consider: {replacement}")

        if r["cves"]:
            print(f"   🚨 {r['cve_count']} CVE(s) found:")
            for cve in r["cves"]:
                fix = ", ".join(cve["fix_versions"]) or "no fix yet"
                print(f"      • {cve['id']}  fix→ {fix}")
                if cve["description"]:
                    print(f"        {cve['description'][:120]}...")

        if r["pypi_error"]:
            print(f"   ⚠️  PyPI lookup error: {r['pypi_error']}")

    # Summary counts
    critical = sum(1 for r in results if r["risk"] == "critical")
    high     = sum(1 for r in results if r["risk"] == "high")
    medium   = sum(1 for r in results if r["risk"] in ("medium", "low-medium"))
    low      = sum(1 for r in results if r["risk"] == "low")

    print("\n" + "=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    print(f"  Total packages  : {len(results)}")
    print(f"  🔴 Critical     : {critical}")
    print(f"  🟠 High         : {high}")
    print(f"  🟡 Medium       : {medium}")
    print(f"  🟢 Low          : {low}")
    print("=" * 60 + "\n")


# Entry Point for Testing 
if __name__ == "__main__":
    # Demo: run against our sample requirements.txt from Phase 1
    from dependency_reader import parse_requirements_txt

    req_file = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("requirements.txt")

    if not req_file.exists():
        print(f"[ERROR] File not found: {req_file}")
        sys.exit(1)

    packages = parse_requirements_txt(req_file)

    print(f"\n Packages found in {req_file}:")
    for pkg, spec in packages.items():
        print(f"  {pkg} {spec}")

    results = audit_packages(packages)
    print_report(results)