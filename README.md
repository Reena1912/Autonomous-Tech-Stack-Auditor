# Autonomous Tech Stack Auditor

A Python tool that scans a repository's dependency files, checks each package against PyPI and a vulnerability database, and produces a structured audit report. It runs locally in a single command, and the included GitHub Actions workflow makes it run automatically on every push that touches your dependencies.

---

## Overview

Most Python projects accumulate dependencies over time. Packages get pinned to old versions, maintainers abandon projects, and CVEs get published against libraries you forgot you were using. None of this shows up until something breaks or, worse, until a security incident.

I built this tool to automate the part of dependency maintenance that nobody does consistently: actually checking whether your packages are still healthy, up to date, and free of known vulnerabilities. It is not a replacement for proper security review, but it gives you a clear picture of your stack's current state without requiring you to manually cross-reference PyPI and CVE databases.

The output is a Markdown file that gets committed back to your repo so there is always a current audit alongside your code.

---

## Features

- Reads `requirements.txt` and `pyproject.toml` (PEP 621 and Poetry formats)
- Extracts package names and version specifications, including extras syntax like `pyjwt[crypto]`
- Fetches current metadata from the PyPI JSON API: latest version, last release date, yanked status
- Runs `pip-audit` to check all packages against the OSS vulnerability advisory database
- Cross-references a curated list of known-deprecated packages and their recommended replacements
- Classifies each package into a risk tier: critical, high, medium, or low
- Generates a structured Markdown report with a summary table, per-package detail, and an action checklist
- Commits `audit_report.md` back to your branch automatically when running in CI
- Posts the full report as a comment on pull requests
- Fails the build when critical CVEs are found, functioning as a security gate

---

## Project Structure

```
.
├── requirements.txt
├── audit_report.md                    # generated output, committed by CI
├── .github/
│   ├── workflows/
│   │   └── stack-audit.yml            # GitHub Actions workflow
│   └── scripts/
│       ├── run_audit.py               # entrypoint called by the workflow
│       ├── dependency_reader.py       # parses requirements.txt / pyproject.toml
│       ├── intelligence.py    # PyPI API + pip-audit + deprecation checks
│       └── report.py        # generates the Markdown report
```

**`dependency_reader.py`**
Handles all dependency file parsing. Returns a `dict[str, str]` mapping package names to their version specifications. Strips extras syntax, handles edge cases like `-r` includes and `--index-url` lines, and normalises package names to lowercase. Both `requirements.txt` and `pyproject.toml` are supported.

**`intelligence.py`**
The core analysis module. Takes the package dict from the reader and runs three checks: a single `pip-audit` subprocess call across all packages (to minimise network round trips), per-package metadata fetches from the PyPI JSON API, and a lookup against a hardcoded deprecated-package registry. Returns a list of structured result dicts, one per package, with a computed risk level.

**`report.py`**
Consumes the results list and produces the Markdown report. Sections are ordered by urgency: critical/high packages first with full CVE detail, then warnings table, then healthy packages, then a checkbox action plan. Also writes `audit_results.json` for use by the workflow steps.

**`run_audit.py`**
A thin entrypoint that wires the three modules together and handles CLI arguments. This is what the GitHub Action calls. You can also run it directly locally with the same command the CI uses, which makes debugging straightforward.

**`.github/workflows/stack-audit.yml`**
The GitHub Actions workflow. Triggers only when dependency files change, runs the audit, writes a job summary, commits the report back to the branch, and posts a PR comment when the event is a pull request. Fails the build if critical vulnerabilities are found.

---

## How It Works

1. The workflow triggers when `requirements.txt` or `pyproject.toml` is modified in a push or pull request.
2. `dependency_reader.py` parses whichever files exist and builds a `{package: version_spec}` dict.
3. `intelligence.py` runs `pip-audit` once against all packages to get CVE data, then hits the PyPI JSON API for each package to get version and staleness information.
4. Each package is assigned a risk level based on whether it has CVEs, is yanked, is in the deprecated registry, or has not had a release in over two years.
5. `report.py` renders the results into sections and writes `audit_report.md`.
6. The workflow commits the report back to the branch with a `[skip ci]` commit message to avoid triggering another run.
7. If the event is a pull request, the full report is posted as a PR comment, updating in place if a bot comment already exists.
8. If any package is rated critical, the workflow exits with a non-zero code and fails the build.

---

## Installation

**Requirements:** Python 3.11 or later.

```bash
# Clone or copy the project into your repo
git clone https://github.com/YOUR_USERNAME/stack-auditor.git
cd stack-auditor
```

**Linux / macOS**

```bash
python -m venv venv
source venv/bin/activate
pip install requests pip-audit
```

**Windows**

```cmd
python -m venv venv
venv\Scripts\activate
pip install requests pip-audit
```

**Verify the install**

```bash
python -m pip_audit --version
python -c "import requests; print(requests.__version__)"
```

Both commands should print a version number without errors.

---

## Usage

**Run against your project locally:**

```bash
PYTHONPATH=".github/scripts" python .github/scripts/run_audit.py \
  --repo-path . \
  --output audit_report.md \
  --json-output audit_results.json
```

**Run against a specific requirements file:**

```bash
PYTHONPATH=".github/scripts" python .github/scripts/run_audit.py \
  --repo-path /path/to/your/project \
  --output my_audit.md \
  --json-output my_results.json
```

**On Windows:**

```cmd
set PYTHONPATH=.github\scripts
python .github\scripts\run_audit.py --repo-path . --output audit_report.md --json-output audit_results.json
```

The command is identical to what the GitHub Action runs, so if it works locally it will work in CI.

---

## Example Output

**Console output during a scan:**

```
[reader] requirements.txt → 9 packages

 Running intelligence scan on 9 packages...

  [1/3] Running pip-audit for CVEs...
        Done. 1 package(s) with known vulnerabilities.

  [2/3] PyPI metadata  (1/9)  flask
  [2/3] PyPI metadata  (2/9)  requests
  [2/3] PyPI metadata  (3/9)  pillow
  ...

[output] JSON results → audit_results.json

 Report written to: audit_report.md

==================================================
  Critical: 1  |  High: 0  |  Total: 9
==================================================
```

**Sample report snippet (critical section):**

```markdown
## Urgent — Action Required

### `pillow` — `CRITICAL`

**2 CVE(s) detected:**

- **CVE-2023-44271** -> fix in `10.0.0`
  > Uncontrolled resource consumption in PIL.ImageFont.ImageFont.getmask()

- **CVE-2023-50447** -> fix in `10.2.0`
  > Arbitrary code execution via crafted image file

**Current spec:** `==9.0.0`  **Latest:** `12.2.0`
```

---

## GitHub Actions Integration

Copy the `.github/` directory into your repository and push. No secrets or additional configuration are required. PyPI is a public API and `pip-audit` uses the OSS advisory database, so there are no API keys involved.

```bash
git add .github/
git commit -m "add: automated dependency audit workflow"
git push origin main
```

After pushing, go to **Actions** in your GitHub repository. You will see the "Tech Stack Audit" workflow appear. If the push modified a dependency file, it will already be running.

**What happens on each trigger:**

- **Push to any branch (dependency files changed):** Full audit runs, report is committed back to the branch, build fails if critical CVEs are found.
- **Pull request (dependency files changed):** Same as above, plus the full report is posted as a comment on the PR. The comment is updated in place on subsequent pushes so the PR thread does not get spammed.
- **Manual trigger:** Available from the Actions tab at any time. Accepts a `fail_on_critical` input so you can run a scan without failing the build if you are auditing mid-release.

**Audit artifacts** (the `.md` and `.json` files) are uploaded and retained for 90 days under the Actions run, so you have a history of past reports even after the branch is deleted.

---

## Risk Classification

**Critical**
The package has one or more entries in the OSS vulnerability advisory database with a known CVE. This means a specific version of the package you are depending on has a documented vulnerability. The action plan will include the fix version where one is available.

**High**
The package has been yanked from PyPI (the maintainer retracted the release), or it appears in the known-deprecated registry with a confirmed replacement. Yanked releases should not be used in production. Deprecated packages may still function but are no longer maintained.

**Medium**
No CVEs found, but the package has not had a release in over two years. This is a signal worth investigating, not necessarily a problem. Some packages are complete and genuinely do not need updates. Others are abandoned. The report flags them so you can decide.

**Low**
No CVEs, not yanked, not deprecated, released within the last two years. No action required.

---

## Current Limitations

**pip-audit requires pinned or constrained versions to match CVEs.** If a package is listed as `flask` with no version spec at all, pip-audit cannot check it against the vulnerability database because it does not know which version is installed. The tool will still report metadata for unpinned packages, but CVE checking will be unreliable. Pin your dependencies.

**The deprecated-package list is hardcoded.** PyPI does not have an official deprecation flag, so I maintain a static dict of known cases. It covers the common ones (`pycrypto`, `nose`, `sklearn`, etc.) but it is not exhaustive. Community contributions to this list are welcome.

**PyPI API rate limiting.** The tool makes one request per package to the PyPI JSON API. For repositories with a large number of dependencies (50+), this may occasionally hit rate limits. There is no retry logic currently. Adding exponential backoff would fix this.

**Python-only.** The tool currently only reads `requirements.txt` and `pyproject.toml`. It does not support `package.json`, `Gemfile`, `go.mod`, or any other ecosystem.

**No transitive dependency analysis.** The tool only checks what is explicitly listed in your dependency file. If one of your dependencies depends on a vulnerable package, that will not be caught unless the vulnerable package is also in your direct dependencies.

---

## Future Improvements

These are the things I plan to add next, roughly in order of priority.

**Unused package detection**
Walk the `.py` files in the repo using Python's `ast` module to collect every `import` statement, then diff that set against the declared dependencies. Packages that are declared but never imported are candidates for removal. This is the hardest part of the auditor to get right because of dynamic imports and packages that register themselves as plugins without a direct import.

**Automatic dependency cleanup**
Given the list of unused or vulnerable packages, generate a cleaned `requirements.txt` with removals applied and upgrades pinned to the fixed versions. Write it to a new file for review rather than modifying the original in place.

**Pull request generation**
Use the GitHub API to open a PR with the cleaned dependency file and the audit report as the PR description. This closes the loop from "report found issues" to "here is the fix, ready to merge."

**Dependency graph visualisation**
Build a tree showing what depends on what, so you can see transitive relationships and identify which of your direct dependencies are pulling in vulnerable transitive ones.

**Multi-language support**
Extend the reader to handle `package.json` (npm) and `pyproject.toml` with `[build-system]` tables. The intelligence and reporter layers are language-agnostic already; the work is in the reader and in replacing `pip-audit` with the appropriate scanner per ecosystem.

---


