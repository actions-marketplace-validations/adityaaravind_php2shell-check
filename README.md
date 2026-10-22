# php2shell-check

[![CVE-2026-109618](https://img.shields.io/badge/CVE-2026--109618-critical-red)](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote)
[![CVE-2026-109619](https://img.shields.io/badge/CVE-2026--109619-critical-red)](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

**Is your PHP exposed to PHP2Shell?** A zero-dependency, read-only checker for the two critical unauthenticated RCE bugs PHP patched on October 21, 2026.

![demo](demo/demo.gif)

> Every run in the GIF is real: the checker probing official `php` Docker images.

> [!IMPORTANT]
> This is a **defensive** tool. It contains **no exploit code**, sends **no network traffic**, and only reads your PHP version and ini settings.

## What is PHP2Shell?

Two memory-safety bugs in PHP core, disclosed together (details leaked Oct 20, fixes shipped Oct 21, 2026). Both are rated **CVSS v4.0 9.2** and exploitable by an **unauthenticated remote attacker**. The affected code path dates back to PHP 5.4.

| CVE | Root cause |
|---|---|
| **CVE-2026-109618** | Out-of-memory hit while request data is only partly initialized; cleanup then trusts that data as valid. |
| **CVE-2026-109619** | Use-after-free: state left over from one request points at freed memory that a later request on the same worker uses. Memory disclosure is also a confirmed impact. |

Every SAPI that serves web requests is in scope: Apache `mod_php` (highest risk), PHP-FPM, `php-cgi`, FrankenPHP, LiteSpeed.

### Affected and fixed versions

| Branch | Status | Verdict from this tool |
|---|---|---|
| 8.5 | Fixed in **8.5.12** | `PATCHED` / `VULNERABLE` |
| 8.4 | Fixed in **8.4.27** | `PATCHED` / `VULNERABLE` |
| 8.3 | Fixed in **8.3.36** | `PATCHED` / `VULNERABLE` |
| 8.2 | Fixed in **8.2.35** | `PATCHED` / `VULNERABLE` |
| 7.4 - 8.1 | No official release; minimal source backports published | `BACKPORT-NEEDED` |
| 5.4 - 7.3 | End-of-life, no fix | `EOL-VULNERABLE` |

## Quick start

```bash
git clone https://github.com/adityaaravind/php2shell-check.git
cd php2shell-check
./php2shell_check.py                 # probes the `php` on your PATH
```

```bash
./php2shell_check.py --php /usr/bin/php8.3          # a specific binary
./php2shell_check.py --version 8.4.26 --json        # offline, e.g. from an inventory export
./php2shell_check.py --version 8.5.11 \
    --ini memory_limit=-1 --ini session.upload_progress.enabled=0
```

### Exit codes (CI / fleet friendly)

| Code | Meaning |
|---|---|
| `0` | Patched |
| `1` | Not patched (vulnerable, backport needed, EOL, or unknown branch) |
| `2` | Error (no PHP found, unparseable version) |

```bash
# Fail a pipeline on an unpatched image
docker run --rm my-app:latest php -r 'echo PHP_VERSION;' \
  | xargs -I{} ./php2shell_check.py --version {} || exit 1
```

### Try it against Docker images

`demo/dphp.sh` lets the checker probe PHP inside a container:

```bash
IMAGE=php:8.4.26-cli ./php2shell_check.py --php demo/dphp.sh
IMAGE=php:8.4.26-cli PHP_ARGS="-d memory_limit=-1 -d session.upload_progress.enabled=0" \
    ./php2shell_check.py --php demo/dphp.sh
python3 demo/make_gif.py   # regenerate demo/demo.gif (needs Docker + Pillow)
```

## Interim mitigations

**Patching is the only complete fix.** These settings reduce exposure while you roll out upgrades. The tool shows which are applied when you are not patched.

| CVE | Setting |
|---|---|
| CVE-2026-109618 | `memory_limit=-1`, set so applications cannot override it |
| CVE-2026-109619 | `session.upload_progress.enabled=0` |
| CVE-2026-109619 (8.5 only) | `fatal_error_backtraces=0` |

Restart **all** PHP workers afterwards. A container/cgroup memory limit is a useful availability boundary but is not a mitigation by itself. CDN/WAF rules (e.g. Cloudflare's) are a stopgap that only cover traffic routed through them.

## Caveats

- **SAPI ini differs from CLI ini.** The CLI may read a different `php.ini` than PHP-FPM or Apache. Run the checker against each SAPI's binary, or check `phpinfo()` served by that SAPI.
- **Distro packages backport fixes without bumping the version.** Ubuntu, Debian, RHEL, etc. may ship a fixed `8.1.x` that still reports an old version string. Confirm against your vendor's advisory.
- **Beware "PoC" repos.** Exploit code for these CVEs is circulating unverified, and some of it may carry malware. Don't run it.

## Tests

```bash
python3 -m unittest discover -s tests
```

## Sources

- [Tenable: PHP2Shell FAQ](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote)
- [Qualys: PHP announces critical security release](https://blog.qualys.com/vulnerabilities-threat-research/2026/10/20/php-announces-critical-security-release-for-two-vulnerabilities)
- [Rapid7 ETR](https://www.rapid7.com/blog/post/etr-cve-2026-109618-and-cve-2026-109619-critical-unauthenticated-remote-code-execution-in-php/)
- [Huntress rapid response](https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities)
- [php.net](https://www.php.net/) - always the authoritative source for versions

## License

MIT. Provided as-is for defensive use; verify findings against official advisories.
