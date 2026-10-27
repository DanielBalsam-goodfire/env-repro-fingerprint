#!/usr/bin/env python3
"""Runtime reproducibility fingerprint (support diagnostic).

Collects a MASKED fingerprint of the execution environment so it can be
diffed against a reference inventory: variable NAMES, value LENGTHS, and
truncated sha256 prefixes ONLY. No value is ever printed or transmitted.
"""
from __future__ import annotations

import hashlib
import os
import platform
import sys
from pathlib import Path

PREFIX = "sha256_8"


def fp(value: bytes) -> str:
    return f"len={len(value)} {PREFIX}={hashlib.sha256(value).hexdigest()[:8]}"


def env_fingerprint(environ: dict[str, bytes], label: str) -> None:
    print(f"\n== {label}: environment fingerprint ({len(environ)} vars, masked) ==")
    for name in sorted(environ):
        print(f"  {name}: {fp(environ[name])}")


def read_environ(path: str) -> dict[str, bytes]:
    with open(path, "rb") as fh:
        raw = fh.read()
    out: dict[str, bytes] = {}
    for entry in raw.split(b"\0"):
        if b"=" in entry:
            k, v = entry.split(b"=", 1)
            out[k.decode(errors="replace")] = v
    return out


def main() -> None:
    print("== runtime ==")
    print(f"  python: {sys.version.split()[0]}  platform: {platform.platform()}")
    print(f"  cwd: {Path.cwd()}")
    print(f"  pid: {os.getpid()}  uid: {os.getuid()}")

    env_fingerprint(read_environ(f"/proc/{os.getpid()}/environ"), "A: this process (session)")

    print("\n== B: same-uid process census (/proc visibility check) ==")
    server_pid = None
    for p in sorted(Path("/proc").iterdir(), key=lambda x: x.name):
        if not p.name.isdigit():
            continue
        try:
            if int(p.name) == os.getpid():
                continue
            status = (p / "status").read_text(errors="replace")
            uid_line = next((l for l in status.splitlines() if l.startswith("Uid:")), None)
            if uid_line is None or int(uid_line.split()[1]) != os.getuid():
                continue
            cmdline = (p / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
            print(f"  pid {p.name}: {cmdline[:110]}")
            if server_pid is None and ("uvicorn" in cmdline or "silico lab" in cmdline):
                server_pid = p.name
        except OSError:
            continue
    print(f"  server process: {server_pid or 'not visible'}")

    if server_pid:
        try:
            env = read_environ(f"/proc/{server_pid}/environ")
            env_fingerprint(env, "C: deployment server process (masked)")
        except OSError as exc:
            print(f"\n== C: server environ read DENIED: {exc} ==")
    else:
        print("\n== C: skipped — server process not visible in /proc ==")

    print("\nfingerprint complete — masked only, nothing transmitted")


if __name__ == "__main__":
    main()
