"""
-----------------------
Phase 2: Intelligence layer for the Tech Stack Auditor.
"""

import json
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import requests

PYPI_API = "https://pypi.org/pypi/{package}/json"
STALE_THRESHOLD_DAYS = 730

KNOWN_DEPRECATED = {
    "pycrypto": "pycryptodome",
    "sha": "hashlib (stdlib)",
    "md5": "hashlib (stdlib)",
    "sklearn": "scikit-learn",
    "beautifulsoup": "beautifulsoup4",
    "flask-script": "flask CLI (built-in)",
    "python-dateutil": "dateutil is fine but check if datetime stdlib covers your need",
    "nose": "pytest",
    "mock": "unittest.mock (stdlib)",
    "simplejson": "json (stdlib)",
    "unipath": "pathlib (stdlib)",
    "futures": "concurrent.futures (stdlib)",
    "functools32": "functools (stdlib)",
    "pkg_resources": "importlib.resources (stdlib)",
    "safety": "pip-audit (Safety went commercial)",
}

def fetch_pypi_metadata(package: str) -> dict:
    url = PYPI_API.format(package=package)
    try:
        resp = requests.get(url, timeout=8)
        if resp.status_code == 404:
            return {"error": "not_found_on_pypi"}
        resp.raise_for_status()
        data = resp.json()
        info = data.get("info", {})
        releases = data.get("releases", {})
        latest_version = info.get("version", "unknown")
        latest_date = None
        for version, files in releases.items():
            for f in files:
                upload_time = f.get("upload_time_iso_8601") or f.get("upload_time")
                if upload_time:
                    try:
                        dt = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
                        if latest_date is None or dt > latest_date:
                            latest_date = dt
                    except ValueError:
                        pass
        days_since_update = None
        if latest_date:
            now = datetime.now(timezone.utc)
            days_since_update = (now - latest_date).days
        return {
            "latest_version":    latest_version,
            "last_updated_days": days_since_update,
            "last_updated_date": latest_date.strftime("%Y-%m-%d") if latest_date else "unknown",
            "is_yanked":         info.get("yanked", False),
            "summary":           info.get("summary", ""),
        }
    except requests.RequestException as e:
        return {"error": str(e)}


def run_pip_audit(packages: dict[str, str]) -> dict[str, list[dict]]:
    req_lines = [f"{pkg}{spec}" if spec else pkg for pkg, spec in packages.items()]
    req_content = "\n".join(req_lines)
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as tmp:
        tmp.write(req_content)
        tmp_req = Path(tmp.name)
    result = subprocess.run(
        [sys.executable, "-m", "pip_audit", "--requirement", str(tmp_req),
         "--format", "json", "--progress-spinner", "off", "--skip-editable"],
        capture_output=True, text=True,
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
                {"id": v.get("id", ""), "aliases": v.get("aliases", []),
                 "fix_versions": v.get("fix_versions", []),
                 "description": v.get("description", "")[:200]}
                for v in vulns
            ]
    return vulnerabilities


def classify_staleness(days: int | None) -> str:
    if days is None:
        return "unknown"
    if days > STALE_THRESHOLD_DAYS:
        return "stale"
    if days > 365:
        return "aging"
    return "active"


def audit_packages(packages: dict[str, str]) -> list[dict]:
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
            "package":           pkg,
            "version_spec":      version_spec,
            "risk":              risk,
            "latest_version":    pypi.get("latest_version", "unknown"),
            "last_updated_date": pypi.get("last_updated_date", "unknown"),
            "last_updated_days": pypi.get("last_updated_days"),
            "staleness":         staleness,
            "is_yanked":         pypi.get("is_yanked", False),
            "is_deprecated":     is_deprecated,
            "replacement":       deprecated_replacement,
            "cves":              cves,
            "cve_count":         len(cves),
            "pypi_error":        pypi.get("error"),
        })
    return results