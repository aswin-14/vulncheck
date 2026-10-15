#!/usr/bin/env python3
"""
vulncheck.py - scan a folder or git repo, build an SBOM, check it against the
latest vulnerability database, and produce ONE report:
    package | installed (vulnerable) version | safe version | CVEs

Usage:
    ./vulncheck.py /path/to/project
    ./vulncheck.py https://github.com/user/repo.git
    ./vulncheck.py <target> -o report.html --min-severity high

Needs: python3, git (for repo URLs). First run installs syft + grype into
~/.local/bin (Linux/macOS, needs curl) or %LOCALAPPDATA%\vulncheck\bin
(Windows). The vulnerability DB is refreshed on every run.
"""
import argparse
import datetime as dt
import html
import json
import os
import re
import shutil
import subprocess
import sys
import stat
import tempfile
import urllib.request
import zipfile

WINDOWS = os.name == "nt"
BIN = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "vulncheck", "bin") if WINDOWS \
    else os.path.expanduser("~/.local/bin")
if WINDOWS:
    os.system("")  # turn on ANSI colour support in the Windows console
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
os.environ["PATH"] = BIN + os.pathsep + os.environ.get("PATH", "")
SEV_RANK = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Negligible": 1, "Unknown": 0}
COLOR = {"Critical": "\033[1;41;97m", "High": "\033[1;31m", "Medium": "\033[1;33m",
         "Low": "\033[36m", "Negligible": "\033[2m", "Unknown": "\033[2m"}
RESET = "\033[0m"


def log(msg):
    print(f"\033[1;34m[*]\033[0m {msg}", file=sys.stderr)


def die(msg):
    print(f"\033[1;31m[!] {msg}\033[0m", file=sys.stderr)
    sys.exit(2)


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def install_windows(tool):
    """Download the latest Windows release zip from GitHub and extract <tool>.exe into BIN."""
    api = f"https://api.github.com/repos/anchore/{tool}/releases/latest"
    with urllib.request.urlopen(urllib.request.Request(api, headers={"User-Agent": "vulncheck"})) as r:
        assets = json.load(r)["assets"]
    arch = "arm64" if os.environ.get("PROCESSOR_ARCHITECTURE", "").upper() == "ARM64" else "amd64"
    zips = {a["name"].rsplit("_", 1)[-1]: a["browser_download_url"] for a in assets
            if "_windows_" in a["name"] and a["name"].endswith(".zip")}
    url = zips.get(f"{arch}.zip") or zips["amd64.zip"]  # arm64 Windows runs amd64 builds too
    zpath = os.path.join(BIN, f"{tool}.zip")
    urllib.request.urlretrieve(url, zpath)
    with zipfile.ZipFile(zpath) as z:
        z.extract(f"{tool}.exe", BIN)
    os.remove(zpath)


def ensure_tools():
    os.makedirs(BIN, exist_ok=True)
    for tool in ("syft", "grype"):
        if shutil.which(tool):
            continue
        log(f"Installing {tool} -> {BIN}")
        if WINDOWS:
            try:
                install_windows(tool)
            except Exception as ex:
                die(f"could not install {tool}: {ex}")
            if not shutil.which(tool):
                die(f"could not install {tool}")
            continue
        url = f"https://raw.githubusercontent.com/anchore/{tool}/main/install.sh"
        r = subprocess.run(f"curl -sSfL {url} | sh -s -- -b {BIN}", shell=True,
                           capture_output=True, text=True)
        if r.returncode != 0 or not shutil.which(tool):
            die(f"could not install {tool}:\n{r.stderr}")


def update_db():
    log("Updating vulnerability database (latest feed)...")
    r = run(["grype", "db", "update"])
    msg = (r.stdout + r.stderr).strip().splitlines()
    if msg:
        log("  " + msg[-1])
    st = run(["grype", "db", "status"]).stdout
    built = re.search(r"Built:\s*(\S+)", st)
    return built.group(1) if built else "unknown"


def is_git_url(t):
    return bool(re.match(r"^(https?://|git@|ssh://|git://)", t)) or t.endswith(".git") and not os.path.isdir(t)


def get_source(target, tmp):
    if is_git_url(target):
        if not shutil.which("git"):
            die("git is not installed")
        dest = os.path.join(tmp, "repo")
        log(f"Cloning {target} ...")
        r = run(["git", "clone", "--depth", "1", target, dest])
        if r.returncode != 0:
            die(f"git clone failed:\n{r.stderr}")
        return dest, target
    if not os.path.isdir(target):
        die(f"not a directory or git URL: {target}")
    return os.path.abspath(target), os.path.abspath(target)


def vkey(v):
    """Rough version sort key: '2.2.28' -> (2,2,28); handles 'v', '-rc1', '1:2.3' epochs."""
    v = str(v).lstrip("vV").split(":")[-1]
    parts = re.split(r"[.\-+_~]", v)
    key = []
    for p in parts:
        m = re.match(r"(\d+)(.*)", p)
        if m:
            key.append((1, int(m.group(1)), m.group(2)))
        else:
            key.append((0, 0, p))  # pre-release tags sort below numbers
    return tuple(key)


def pick_fix(installed, fixes):
    """Smallest fixed version that is newer than the installed one."""
    newer = [f for f in fixes if vkey(f) > vkey(installed)]
    return min(newer, key=vkey) if newer else (min(fixes, key=vkey) if fixes else None)


def scan(src):
    log("Scanning code base -> SBOM (syft)...")
    r = run(["syft", f"dir:{src}", "-q", "-o", "cyclonedx-json",
             "--exclude", "./**/.git/**"])
    if r.returncode != 0:
        die(f"syft failed:\n{r.stderr}")
    sbom = r.stdout
    pkgs = len(json.loads(sbom).get("components", []))
    log(f"SBOM built: {pkgs} packages")

    log("Matching SBOM against vulnerability DB (grype)...")
    r = run(["grype", "-q", "-o", "json"], input=sbom)
    if r.returncode not in (0, 1):
        die(f"grype failed:\n{r.stderr}")
    return json.loads(r.stdout), pkgs, sbom


def aggregate(result, min_rank):
    """One row per vulnerable package with the version that fixes ALL its CVEs."""
    rows = {}
    for m in result.get("matches", []):
        a, v = m["artifact"], m["vulnerability"]
        sev = v.get("severity", "Unknown")
        if SEV_RANK.get(sev, 0) < min_rank:
            continue
        k = (a["type"], a["name"], a["version"])
        row = rows.setdefault(k, {
            "ecosystem": a["type"], "name": a["name"], "installed": a["version"],
            "severity": "Unknown", "vulns": [], "fixes": [], "unfixed": [],
            "locations": sorted({l.get("path", "") for l in a.get("locations", [])}),
        })
        if SEV_RANK.get(sev, 0) > SEV_RANK[row["severity"]]:
            row["severity"] = sev
        ids = {v["id"]} | {rv["id"] for rv in m.get("relatedVulnerabilities", [])}
        cve = sorted(i for i in ids if i.startswith("CVE-"))
        label = v["id"] + (f" ({cve[0]})" if cve and cve[0] != v["id"] else "")
        if label not in [x["id"] for x in row["vulns"]]:
            fix = pick_fix(a["version"], v.get("fix", {}).get("versions", []))
            row["vulns"].append({"id": label, "severity": sev, "fix": fix,
                                 "url": v.get("dataSource", "")})
            (row["fixes"] if fix else row["unfixed"]).append(fix or v["id"])

    out = []
    for row in rows.values():
        row["safe"] = max(row["fixes"], key=vkey) if row["fixes"] else None
        row["vulns"].sort(key=lambda x: -SEV_RANK.get(x["severity"], 0))
        out.append(row)
    out.sort(key=lambda r: (-SEV_RANK[r["severity"]], r["name"]))
    return out


def print_console(rows, totals):
    if not rows:
        print("\n\033[1;32m✔ No known vulnerable packages found.\033[0m")
        return
    w = max(len(r["name"]) for r in rows) + 2
    print(f"\n{'SEVERITY':<11}{'PACKAGE':<{w}}{'ECOSYSTEM':<12}{'VULNERABLE':<16}{'SAFE VERSION':<16}VULNS")
    print("-" * (w + 70))
    for r in rows:
        safe = r["safe"] or "NO FIX YET"
        if r["safe"] and r["unfixed"]:
            safe += "*"
        print(f"{COLOR[r['severity']]}{r['severity']:<11}{RESET}{r['name']:<{w}}"
              f"{r['ecosystem']:<12}{r['installed']:<16}\033[1;32m{safe:<16}{RESET}{len(r['vulns'])}")
    print("-" * (w + 70))
    print("  " + "   ".join(f"{k}: {v}" for k, v in totals.items()))
    if any(r["safe"] and r["unfixed"] for r in rows):
        print("  * some CVEs for this package have no fix released yet")


def write_html(path, rows, totals, meta):
    e = html.escape
    body = []
    for r in rows:
        vl = "".join(
            f'<li><span class="pill {e(v["severity"])}">{e(v["severity"])}</span> '
            f'<a href="{e(v["url"])}" target="_blank">{e(v["id"])}</a> '
            f'&rarr; fixed in <b>{e(v["fix"] or "no fix yet")}</b></li>' for v in r["vulns"])
        safe = e(r["safe"]) if r["safe"] else '<span class="nofix">no fix yet</span>'
        if r["safe"] and r["unfixed"]:
            safe += ' <span class="nofix">(+ unfixed CVEs)</span>'
        body.append(
            f'<tr><td><span class="pill {e(r["severity"])}">{e(r["severity"])}</span></td>'
            f'<td><b>{e(r["name"])}</b><div class="loc">{e(", ".join(r["locations"]))}</div></td>'
            f'<td>{e(r["ecosystem"])}</td><td class="bad">{e(r["installed"])}</td>'
            f'<td class="good">{safe}</td>'
            f'<td><details><summary>{len(r["vulns"])} vulnerabilities</summary><ul>{vl}</ul></details></td></tr>')
    tiles = "".join(f'<div class="tile {k}"><div class="n">{v}</div>{k}</div>' for k, v in totals.items())
    doc = f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vulnerability Report</title><style>
:root{{--bg:#f7f7f9;--card:#fff;--fg:#1d1d1f;--mut:#6b6b76;--line:#e3e3e8}}
@media (prefers-color-scheme:dark){{:root{{--bg:#16161a;--card:#1f1f25;--fg:#ececf1;--mut:#9a9aa6;--line:#33333c}}}}
body{{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,sans-serif}}
main{{max-width:1200px;margin:auto;padding:24px 16px}}
h1{{margin:0 0 4px}} .meta{{color:var(--mut);margin-bottom:20px}}
.tiles{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}}
.tile{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 18px;min-width:90px;color:var(--mut)}}
.tile .n{{font-size:26px;font-weight:700;color:var(--fg)}}
.wrap{{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}}
table{{border-collapse:collapse;width:100%}} th,td{{padding:10px 12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}
th{{font-size:12px;text-transform:uppercase;color:var(--mut)}}
.pill{{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;color:#fff;background:#888}}
.Critical{{background:#b3261e}} .High{{background:#e8590c}} .Medium{{background:#c99400}} .Low{{background:#1971c2}}
.tile.Critical,.tile.High,.tile.Medium,.tile.Low{{background:var(--card)}}
.tile.Critical .n{{color:#d93a2f}} .tile.High .n{{color:#e8590c}} .tile.Medium .n{{color:#c99400}} .tile.Low .n{{color:#1971c2}}
.bad{{color:#d93a2f;font-family:monospace;font-weight:600}} .good{{color:#2b8a3e;font-family:monospace;font-weight:600}}
.nofix{{color:var(--mut);font-weight:400;font-family:system-ui}} .loc{{color:var(--mut);font-size:12px}}
ul{{margin:6px 0 0;padding-left:18px}} a{{color:inherit}} summary{{cursor:pointer}}
.ok{{padding:24px;font-size:18px;color:#2b8a3e}}
</style></head><body><main>
<h1>Vulnerability Report</h1>
<div class="meta">Target: <b>{e(meta['target'])}</b><br>
Scanned: {e(meta['time'])} &middot; Packages in SBOM: {meta['pkgs']} &middot;
Vulnerability DB built: {e(meta['db'])}</div>
<div class="tiles"><div class="tile"><div class="n">{len(rows)}</div>Vulnerable pkgs</div>{tiles}</div>
<div class="wrap">{"<table><tr><th>Severity</th><th>Package</th><th>Ecosystem</th><th>Vulnerable version</th><th>Safe version</th><th>Details</th></tr>" + "".join(body) + "</table>" if rows else '<div class="ok">✔ No known vulnerable packages found.</div>'}</div>
<p class="meta">“Safe version” = lowest version that fixes every known vulnerability for that package as of the DB date.</p>
</main></body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)


def main():
    ap = argparse.ArgumentParser(description="SBOM + vulnerability report for a folder or git repo")
    ap.add_argument("target", help="folder path or git URL")
    ap.add_argument("-o", "--output", default="vuln-report.html", help="report file (default: vuln-report.html)")
    ap.add_argument("--min-severity", default="low", choices=[s.lower() for s in SEV_RANK],
                    help="hide findings below this severity (default: low)")
    ap.add_argument("--fail-on", default="high", choices=[s.lower() for s in SEV_RANK],
                    help="exit 1 if any finding at/above this severity (default: high)")
    ap.add_argument("--sbom", help="also save the SBOM (CycloneDX JSON) to this path")
    args = ap.parse_args()

    ensure_tools()
    db_built = update_db()
    tmp = tempfile.mkdtemp(prefix="vulncheck-")
    try:
        src, label = get_source(args.target, tmp)
        result, pkgs, sbom = scan(src)
    finally:
        # git marks .git objects read-only; Windows refuses to delete those without this
        shutil.rmtree(tmp, onerror=lambda f, p, _: (os.chmod(p, stat.S_IWRITE), f(p)))
    if args.sbom:
        with open(args.sbom, "w", encoding="utf-8") as f:
            f.write(sbom)

    min_rank = SEV_RANK[args.min_severity.capitalize()]
    rows = aggregate(result, min_rank)
    totals = {s: sum(1 for r in rows if r["severity"] == s) for s in ("Critical", "High", "Medium", "Low")}

    print_console(rows, totals)
    write_html(args.output, rows, totals, {
        "target": label, "pkgs": pkgs, "db": db_built,
        "time": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
    print(f"\n  Report: {os.path.abspath(args.output)}")

    fail_rank = SEV_RANK[args.fail_on.capitalize()]
    if any(SEV_RANK[r["severity"]] >= fail_rank for r in rows):
        print(f"\033[1;31m  ALERT: packages with {args.fail_on}+ vulnerabilities found\033[0m")
        sys.exit(1)


if __name__ == "__main__":
    main()
