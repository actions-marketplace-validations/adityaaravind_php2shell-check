#!/usr/bin/env python3
"""php2shell-check: defensive exposure checker for CVE-2026-109618 / CVE-2026-109619.

Compares a PHP version against the fixed releases and inspects the interim
ini mitigations. Contains no exploit code and sends no network traffic.
"""
import argparse
import json
import re
import subprocess
import sys

CVES = ["CVE-2026-109618", "CVE-2026-109619"]

# Branch -> first fixed release (official).
FIXED = {(8, 5): (8, 5, 12), (8, 4): (8, 4, 27), (8, 3): (8, 3, 36), (8, 2): (8, 2, 35)}

INI_KEYS = ["memory_limit", "session.upload_progress.enabled", "fatal_error_backtraces"]


def parse_version(text):
    m = re.match(r"\s*(\d+)\.(\d+)\.(\d+)", text)
    if not m:
        raise ValueError(f"cannot parse PHP version: {text!r}")
    return tuple(int(x) for x in m.groups())


def classify(version):
    """Return (status, detail) for a (major, minor, patch) tuple."""
    branch = version[:2]
    if branch in FIXED:
        fixed = FIXED[branch]
        if version >= fixed:
            return "patched", f"{'.'.join(map(str, version))} >= {'.'.join(map(str, fixed))}"
        return "vulnerable", f"upgrade to {'.'.join(map(str, fixed))} or later"
    if (7, 4) <= branch < (8, 2):
        return "backport-needed", (
            "no official release; apply source backport or verify distro patch"
        )
    if branch < (7, 4):
        return "eol-vulnerable", "end-of-life, no fix; migrate to a supported branch"
    return "unknown", "branch newer than this tool knows; check php.net"


def truthy(value):
    return str(value).strip().lower() in ("1", "on", "true", "yes")


def check_mitigations(ini, version):
    """Interim hardening from the PHP advisory. Reduces exposure, does not fix."""
    out = []
    mem = str(ini.get("memory_limit", "")).strip()
    out.append({
        "cve": "CVE-2026-109618",
        "setting": "memory_limit=-1",
        "applied": mem == "-1",
        "current": mem or "unset",
    })
    up = ini.get("session.upload_progress.enabled")
    out.append({
        "cve": "CVE-2026-109619",
        "setting": "session.upload_progress.enabled=0",
        "applied": up is not None and not truthy(up),
        "current": "unset" if up is None else str(up),
    })
    if version[:2] == (8, 5):
        fb = ini.get("fatal_error_backtraces")
        out.append({
            "cve": "CVE-2026-109619",
            "setting": "fatal_error_backtraces=0 (PHP 8.5 only)",
            "applied": fb is not None and not truthy(fb),
            "current": "unset" if fb is None else str(fb),
        })
    return out


def probe_local_with_ini(php_bin):
    """Like probe_local but honours php.ini (drops -n)."""
    code = "echo PHP_VERSION,\"\\n\";" + "".join(
        f'echo "{k}=",ini_get("{k}"),"\\n";' for k in INI_KEYS
    )
    res = subprocess.run([php_bin, "-r", code], capture_output=True, text=True, timeout=60)
    if res.returncode != 0:
        raise RuntimeError(res.stderr.strip() or "php probe failed")
    lines = res.stdout.splitlines()
    ini = dict(l.split("=", 1) for l in lines[1:] if "=" in l)
    return lines[0], ini


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--php", default="php", help="php binary to probe (default: php)")
    p.add_argument("--version", help="check this version string instead of probing")
    p.add_argument("--ini", action="append", default=[], metavar="KEY=VAL",
                   help="ini value to assume when using --version (repeatable)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    args = p.parse_args(argv)

    try:
        if args.version:
            raw, ini = args.version, dict(i.split("=", 1) for i in args.ini)
        else:
            raw, ini = probe_local_with_ini(args.php)
        version = parse_version(raw)
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    status, detail = classify(version)
    mitig = check_mitigations(ini, version)
    report = {"cves": CVES, "version": raw.strip(), "status": status,
              "detail": detail, "mitigations": mitig,
              "note": "CLI ini may differ from FPM/Apache SAPI ini; check each SAPI."}

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"PHP {report['version']}: {status.upper()} - {detail}")
        if status != "patched":
            print("Interim mitigations (reduce exposure, do NOT fix):")
            for m in mitig:
                print(f"  [{'x' if m['applied'] else ' '}] {m['setting']} (current: {m['current']})")
        print(f"Note: {report['note']}")
    return 0 if status == "patched" else 1


if __name__ == "__main__":
    sys.exit(main())
