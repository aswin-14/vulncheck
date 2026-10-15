# vulncheck

Scan a folder or git repo, build an SBOM, check it against the latest vulnerability
database, and get one report: **package | vulnerable version | safe version | CVEs**.

Uses [syft](https://github.com/anchore/syft) and [grype](https://github.com/anchore/grype).
Both are installed automatically on the first run.

## Requirements

- Python 3.10+
- git (only for scanning repo URLs)
- curl (Linux/macOS only, for the first-run install)

## Usage

```bash
vulncheck /path/to/project
vulncheck https://github.com/user/repo.git
vulncheck <target> -o report.html --min-severity high --fail-on critical --sbom sbom.json
```

The HTML report is written to `vuln-report.html` in the current folder unless you pass `-o`.
The exit code is 1 if any finding is at or above `--fail-on` (default: `high`), so it can be used in CI.

## Install

### Linux / macOS

```bash
mkdir -p ~/.local/bin
curl -sSfL https://raw.githubusercontent.com/aswin-14/vulncheck/main/vulncheck.py -o ~/.local/bin/vulncheck
chmod +x ~/.local/bin/vulncheck
```

Make sure `~/.local/bin` is on your `PATH`.

### Windows

1. Install Python from python.org (tick **Add python.exe to PATH**) and, optionally, Git for Windows.
2. Save `vulncheck.py` to e.g. `C:\tools\`, and next to it create `vulncheck.bat`:
   ```bat
   @python "%~dp0vulncheck.py" %*
   ```
3. Add `C:\tools` to your PATH (then open a new terminal):
   ```powershell
   [Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\tools", "User")
   ```

syft and grype are downloaded to `%LOCALAPPDATA%\vulncheck\bin` on the first run.
