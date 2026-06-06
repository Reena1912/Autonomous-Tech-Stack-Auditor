import re
import sys
from pathlib import Path


def parse_requirements_txt(filepath: Path) -> dict[str, str]:
    """Parse requirements.txt → {package_name: version_spec}"""
    packages = {}
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            match = re.match(r"^([A-Za-z0-9_.\-]+(?:\[[^\]]+\])?)\s*(.*)$", line)
            if match:
                raw_name = match.group(1)
                # strip extras like [crypto]
                name = re.sub(r"\[.*?\]", "", raw_name).lower().strip()
                spec = match.group(2).strip()
                if name:
                    packages[name] = spec
    return packages


def parse_pyproject_toml(filepath: Path) -> dict[str, str]:
    """Parse pyproject.toml → {package_name: version_spec}"""
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            print("  [!] tomllib not available. Run: pip install tomli")
            return {}
    packages = {}
    with open(filepath, "rb") as f:
        data = tomllib.load(f)
    # PEP 621
    for dep in data.get("project", {}).get("dependencies", []):
        m = re.match(r"^([A-Za-z0-9_.\-]+)(.*)", dep)
        if m:
            packages[m.group(1).lower()] = m.group(2).strip()
    # Poetry
    for name, val in data.get("tool", {}).get("poetry", {}).get("dependencies", {}).items():
        if name.lower() != "python":
            packages[name.lower()] = val if isinstance(val, str) else ""
    return packages


def scan_folder(folder_path: str) -> dict[str, str]:
    folder = Path(folder_path).resolve()
    if not folder.exists():
        print(f"[ERROR] Folder not found: {folder}")
        sys.exit(1)
    packages: dict[str, str] = {}
    req_file = folder / "requirements.txt"
    if req_file.exists():
        found = parse_requirements_txt(req_file)
        packages.update(found)
        print(f"  requirements.txt  → {len(found)} packages")
    pyproject_file = folder / "pyproject.toml"
    if pyproject_file.exists():
        found = parse_pyproject_toml(pyproject_file)
        packages.update(found)
        print(f"  pyproject.toml    → {len(found)} packages")
    if not packages:
        print("  [!] No dependency files found.")
    return packages


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    pkgs = scan_folder(target)
    for name, spec in pkgs.items():
        print(f"  {name}{spec}")