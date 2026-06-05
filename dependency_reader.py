import re
import sys
from pathlib import Path


def parse_requirements_txt(filepath: Path) -> dict[str, str]:
    """Parse a requirements.txt file and return package names with version specs."""
    packages = {}

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            if line.startswith("-"):
                continue

            match = re.match(r"^([A-Za-z0-9_.-]+)(.*)$", line)
            if match:
                package_name = match.group(1).lower()
                version_spec = match.group(2).strip()
                packages[package_name] = version_spec

    return packages


def parse_pyproject_toml(filepath: Path) -> list[str]:
    """Parse a pyproject.toml file and return list of package names."""
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            print("  [!] tomllib not available. Run: pip install tomli")
            return []

    packages = []

    with open(filepath, "rb") as f:
        data = tomllib.load(f)

    # PEP 621 style: [project] dependencies
    project_deps = data.get("project", {}).get("dependencies", [])
    for dep in project_deps:
        name = re.split(r"[>=<!~\[\s;@]", dep)[0].strip()
        if name:
            packages.append(name)

    # Poetry style: [tool.poetry.dependencies]
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for name in poetry_deps:
        if name.lower() != "python":
            packages.append(name)

    return packages


def scan_folder(folder_path: str) -> None:
    """Scan a folder for dependency files and print found packages."""
    folder = Path(folder_path).resolve()

    if not folder.exists():
        print(f"[ERROR] Folder not found: {folder}")
        sys.exit(1)

    print(f"\n Scanning: {folder}\n")
    print("=" * 50)

    found_any = False

    # requirements.txt
    req_file = folder / "requirements.txt"
    if req_file.exists():
        found_any = True
        packages = parse_requirements_txt(req_file)
        print(f"\n requirements.txt  ({len(packages)} packages found)\n")
        for pkg, version in packages.items():
            print(f"   {pkg} {version}")

    # pyproject.toml
    pyproject_file = folder / "pyproject.toml"
    if pyproject_file.exists():
        found_any = True
        packages = parse_pyproject_toml(pyproject_file)
        print(f"\n pyproject.toml  ({len(packages)} packages found)\n")
        for pkg in packages:
            print(f"   {pkg}")

    if not found_any:
        print("\n [!] No dependency files found.")
        print("     Expected: requirements.txt or pyproject.toml")

    print("\n" + "=" * 50)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    scan_folder(target)