#!/usr/bin/env python3
"""Strictly bounded evidence collector for authorized web assessments."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
CAPTURE_BYTES = 262_144
HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


@dataclass(frozen=True)
class Target:
    url: str
    scheme: str
    hostname: str
    port: int
    path: str


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Collect bounded evidence for an explicitly authorized web-security assessment."
    )
    p.add_argument("target", nargs="?", help="Exact in-scope http(s) URL without query parameters")
    p.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm you own the target or have explicit permission to assess it",
    )
    p.add_argument(
        "--scope-note",
        required=True,
        help="Non-secret authorization reference, ticket, owner, and scope note",
    )
    p.add_argument("--mode", choices=("passive", "safe"), default="passive")
    p.add_argument(
        "--allow-host-scan",
        action="store_true",
        help="Separately confirm permission for one bounded Nmap probe of the target URL's exact port",
    )
    p.add_argument("--plan", action="store_true", help="Print planned checks without sending requests")
    return p


def valid_hostname(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass
    try:
        ascii_host = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return False
    if not HOST_RE.fullmatch(ascii_host) or ".." in ascii_host:
        return False
    return all(
        label and len(label) <= 63 and not label.startswith("-") and not label.endswith("-")
        for label in ascii_host.rstrip(".").split(".")
    )


def parse_and_validate_target(raw: str) -> Target:
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("target must be an http or https URL with a hostname")
    if parsed.username or parsed.password:
        raise ValueError("do not place credentials in the target URL")
    if parsed.query or parsed.fragment:
        raise ValueError("query strings and fragments are rejected to prevent secret leakage; use an exact clean URL")
    if any(ord(char) < 32 or char.isspace() for char in raw):
        raise ValueError("target contains invalid whitespace or control characters")
    if not valid_hostname(parsed.hostname):
        raise ValueError("target hostname is invalid or option-like")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("target port is malformed") from exc
    if not 1 <= port <= 65535:
        raise ValueError("target port must be between 1 and 65535")
    path = parsed.path or "/"
    return Target(raw, parsed.scheme, parsed.hostname, port, path)


def planned(mode: str, target: Target) -> list[str]:
    checks = [
        "DNS A/AAAA lookup with two-second retries",
        "Exact URL HTTP capture: zero redirects, 256 KiB maximum, no credentials",
        "WhatWeb aggression 1: one request, one thread, zero redirects",
    ]
    if target.scheme == "https":
        checks.append("TLS certificate handshake metadata with a 25-second process timeout")
    if mode == "safe":
        checks.append(f"Nmap version-light probe of the single authorized port {target.port}")
    return checks


def build_commands(args: argparse.Namespace, target: Target, out: Path):
    commands: list[tuple[list[str], Path, int]] = [
        (["dig", "+time=2", "+tries=1", "+short", "A", target.hostname], out / "dns-a.txt", 7),
        (["dig", "+time=2", "+tries=1", "+short", "AAAA", target.hostname], out / "dns-aaaa.txt", 7),
        ([
            "curl", "--silent", "--show-error", "--connect-timeout", "5", "--max-time", "20",
            "--max-filesize", str(CAPTURE_BYTES), "--range", f"0-{CAPTURE_BYTES - 1}",
            "--dump-header", str(out / "headers.txt"), "--output", str(out / "landing.html"),
            target.url,
        ], out / "curl.log", 25),
        ([
            "whatweb", "--no-errors", "--color=never", "--aggression=1", "--max-threads=1",
            "--follow-redirect=never", "--max-redirects=0", "--open-timeout=5", "--read-timeout=10",
            "--wait=1", "--no-cookies", target.url,
        ], out / "whatweb.txt", 25),
    ]
    if target.scheme == "https":
        commands.append(([
            "openssl", "s_client", "-connect", f"{target.hostname}:{target.port}",
            "-servername", target.hostname, "-brief",
        ], out / "tls-certificate.txt", 25))
    if args.mode == "safe":
        commands.append(([
            "nmap", "-Pn", "-sV", "--version-light", "-T2", "--max-retries", "1",
            "--host-timeout", "30s", "-p", str(target.port), target.hostname,
        ], out / "nmap-authorized-port.txt", 40))
    return commands


def private_write(path: Path, text: str) -> None:
    path.write_text(text)
    path.chmod(0o600)


def run(command: list[str], output: Path, timeout: int) -> dict:
    local_tool = ROOT / "bin" / command[0]
    executable = str(local_tool) if local_tool.is_file() else shutil.which(command[0])
    if not executable:
        private_write(output, f"SKIPPED: {command[0]} is not installed\n")
        return {"tool": command[0], "status": "missing", "exit_code": None}
    resolved = [executable, *command[1:]]
    display = shlex.join(resolved)
    try:
        completed = subprocess.run(resolved, text=True, capture_output=True, timeout=timeout, shell=False)
        private_write(output, f"$ {display}\n\nSTDOUT\n{completed.stdout}\nSTDERR\n{completed.stderr}")
        status = "completed" if completed.returncode == 0 else "failed"
        return {"tool": Path(executable).name, "status": status, "exit_code": completed.returncode}
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        private_write(output, f"$ {display}\n\nTIMED OUT AFTER {timeout}s\n{stdout}")
        return {"tool": Path(executable).name, "status": "timeout", "exit_code": None}
    except OSError as exc:
        private_write(output, f"$ {display}\n\nEXECUTION ERROR\n{type(exc).__name__}: {exc}\n")
        return {"tool": Path(executable).name, "status": "error", "exit_code": None}


def redact_headers(path: Path) -> None:
    if not path.exists():
        return
    text = path.read_text(errors="replace")
    text = re.sub(r"(?im)^(set-cookie\s*:).*$", r"\1 [REDACTED]", text)
    private_write(path, text)


def main() -> int:
    p = parser()
    args = p.parse_args()
    if not args.target:
        p.error("a target URL is required")
    if not args.authorized:
        p.error("explicit authorization confirmation is required")
    if len(args.scope_note.strip()) < 8:
        p.error("scope note must contain a meaningful non-secret authorization reference")
    try:
        target = parse_and_validate_target(args.target)
    except ValueError as exc:
        p.error(str(exc))
    if args.mode == "safe" and not args.allow_host_scan:
        p.error("safe mode requires separate host-level permission: add --allow-host-scan only when authorized")

    checks = planned(args.mode, target)
    if args.plan:
        print(f"Authorized {args.mode} assessment plan for {target.url}:")
        for check in checks:
            print(f"- {check}")
        return 0

    os.umask(0o077)
    RESULTS.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    safe_host = "".join(ch if ch.isalnum() or ch in ".-_" else "_" for ch in target.hostname)
    out = RESULTS / f"{stamp}_{safe_host}"
    out.mkdir(mode=0o700, exist_ok=False)
    scope = {
        "target": target.url,
        "hostname": target.hostname,
        "port": target.port,
        "path": target.path,
        "mode": args.mode,
        "authorized": True,
        "host_scan_authorized": bool(args.allow_host_scan),
        "scope_note": args.scope_note,
        "started_utc": stamp,
        "rules": ["exact URL", "zero redirects", "256 KiB response cap", "no credentials", "manual verification required"],
    }
    private_write(out / "scope.json", json.dumps(scope, indent=2) + "\n")

    records = [run(command, output, timeout) for command, output, timeout in build_commands(args, target, out)]
    redact_headers(out / "headers.txt")
    private_write(out / "run.json", json.dumps(records, indent=2) + "\n")
    report = f"""# Authorized Web Assessment Evidence

- **Target:** `{target.url}`
- **Mode:** `{args.mode}`
- **Authorization:** Confirmed by operator
- **Scope reference:** `{args.scope_note}`
- **Started (UTC):** `{stamp}`

## Evidence collected

""" + "\n".join(f"- {r['tool']}: {r['status']} (exit {r['exit_code']})" for r in records) + """

## Analyst checklist

- Confirm every observation manually before calling it a vulnerability.
- Separate informational observations from exploitable findings.
- Stop if a response redirects outside the exact authorized URL; redirects are not followed automatically.
- Describe impact without accessing private data.
- Provide remediation and retest evidence.
- Delete the private capture if it contains sensitive content.
"""
    private_write(out / "REPORT.md", report)
    print(out)
    return 0 if all(record["status"] == "completed" for record in records) else 1


if __name__ == "__main__":
    raise SystemExit(main())
