#!/usr/bin/env python3
"""Runtime smoke checks for the brotherhugo.harden role.

Reads the sanitized snapshot written at apply time
(/var/lib/harden/expected.json) and probes the live host.

Does not dump or read admin_user secrets. Does not attempt to trigger bans.
sshd jail uses the systemd journal (ssh.service), not /var/log/auth.log.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

DEFAULT_EXPECTED = "/var/lib/harden/expected.json"
SSHD_JAIL_FILE = "/etc/fail2ban/jail.d/sshd.local"
RKHUNTER_CONF = "/etc/rkhunter.conf"
RKHUNTER_CONF_D = "/etc/rkhunter.conf.d"
UNATTENDED_AUTO = "/etc/apt/apt.conf.d/20auto-upgrades"

OK_SSH_LOGLEVELS = frozenset(
    {"info", "verbose", "debug", "debug1", "debug2", "debug3"}
)
SSH_PORT_ALIASES = {"ssh": 22}


class Reporter:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0
        self.skipped = 0

    def ok(self, name: str, detail: str = "") -> None:
        self.passed += 1
        suffix = f"  {detail}" if detail else ""
        print(f"PASS  {name}{suffix}")

    def fail(self, name: str, detail: str) -> None:
        self.failed += 1
        print(f"FAIL  {name}  {detail}")

    def skip(self, name: str, reason: str) -> None:
        self.skipped += 1
        print(f"SKIP  {name}  {reason}")

    def summary(self) -> int:
        print(
            f"harden-check: {self.passed} passed, {self.failed} failed, "
            f"{self.skipped} skipped"
        )
        return 1 if self.failed else 0


def run(argv: list[str], timeout: int = 30) -> tuple[int, str, str]:
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except FileNotFoundError:
        return 127, "", f"{argv[0]} not found"
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    return proc.returncode, proc.stdout, proc.stderr


def which(name: str, fallback: str | None = None) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    if fallback and os.path.isfile(fallback) and os.access(fallback, os.X_OK):
        return fallback
    return None


def load_expected(path: str) -> dict:
    expected_path = Path(path)
    if not expected_path.is_file():
        raise SystemExit(
            f"FAIL  expected snapshot missing: {path}\n"
            "Apply the role (tag harden-verify) so /var/lib/harden/expected.json exists."
        )
    try:
        data = json.loads(expected_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"FAIL  expected snapshot is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit("FAIL  expected snapshot must be a JSON object")
    return data


def parse_key_values(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip().lower()] = value.strip().strip('"').strip("'")
    return values


def read_file(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError:
        return None


def parse_jail_list(status_out: str) -> list[str]:
    for line in status_out.splitlines():
        if "Jail list:" not in line:
            continue
        _, _, rest = line.partition(":")
        rest = rest.strip()
        if not rest:
            return []
        return [item.strip() for item in rest.split(",") if item.strip()]
    return []


def f2b_get(jail: str, key: str) -> str | None:
    client = which("fail2ban-client", "/usr/bin/fail2ban-client")
    if not client:
        return None
    rc, out, err = run([client, "get", jail, key])
    if rc != 0:
        return None
    text = (out or err).strip()
    return text or None


def sshd_effective() -> tuple[dict[str, str] | None, str]:
    sshd = which("sshd", "/usr/sbin/sshd")
    if not sshd:
        return None, "sshd not found"
    rc, out, err = run([sshd, "-T"])
    if rc != 0:
        return None, (err or out).strip() or f"sshd -T exited {rc}"
    parsed: dict[str, str] = {}
    for line in out.splitlines():
        if not line.strip():
            continue
        key, _, value = line.partition(" ")
        parsed[key.lower()] = value.strip()
    return parsed, ""


def parse_port(value: str | int | None) -> int | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    if text in SSH_PORT_ALIASES:
        return SSH_PORT_ALIASES[text]
    try:
        return int(text)
    except ValueError:
        return None


_SECRET_KEYS = frozenset({"password", "authorized_keys"})


def _contains_secret_keys(node: object) -> bool:
    if isinstance(node, dict):
        for key, value in node.items():
            if str(key).lower() in _SECRET_KEYS:
                return True
            if _contains_secret_keys(value):
                return True
        return False
    if isinstance(node, list):
        return any(_contains_secret_keys(item) for item in node)
    return False


def enabled(node: dict | None, key: str = "enabled") -> bool:
    if not node:
        return False
    return bool(node.get(key))


def check_service_active(rep: Reporter, name: str, unit: str) -> bool:
    rc, out, err = run(["systemctl", "is-active", unit])
    status = (out or err).strip() or f"exit {rc}"
    if status == "active":
        rep.ok(name, unit)
        return True
    rep.fail(name, f"{unit} is {status}")
    return False


def check_ssh(rep: Reporter, expected: dict) -> None:
    ssh = expected.get("ssh") or {}
    if not enabled(ssh):
        rep.skip("sshd", "ssh.enabled is false")
        return

    sshd = which("sshd", "/usr/sbin/sshd")
    if not sshd:
        rep.fail("sshd.binary", "sshd not found")
        return

    rc, out, err = run([sshd, "-t"])
    if rc == 0:
        rep.ok("sshd.config", "sshd -t")
    else:
        rep.fail("sshd.config", (err or out).strip() or f"sshd -t exited {rc}")

    check_service_active(rep, "sshd.service", "ssh")

    parsed, parse_err = sshd_effective()
    if parsed is None:
        rep.fail("sshd.effective", parse_err)
        return

    loglevel = parsed.get("loglevel", "").lower()
    want = str(ssh.get("loglevel") or "INFO").lower()
    if loglevel in OK_SSH_LOGLEVELS:
        rep.ok("sshd.loglevel", loglevel)
    else:
        rep.fail(
            "sshd.loglevel",
            f"{loglevel or '(missing)'} (need {want} or verbose/debug; "
            "quiet/error/fatal hide failed logins from fail2ban)",
        )

    want_port = parse_port(ssh.get("port"))
    have_port = parse_port(parsed.get("port"))
    if want_port is not None and have_port == want_port:
        rep.ok("sshd.port", str(have_port))
    else:
        rep.fail("sshd.port", f"effective {have_port}, expected {want_port}")


def check_fail2ban(rep: Reporter, expected: dict) -> None:
    f2b = expected.get("fail2ban") or {}
    if not enabled(f2b):
        rep.skip("fail2ban", "fail2ban.enabled is false")
        return

    client = which("fail2ban-client", "/usr/bin/fail2ban-client")
    if not client:
        rep.fail("fail2ban.client", "fail2ban-client not found")
        return

    if not check_service_active(rep, "fail2ban.service", "fail2ban"):
        return

    rc, out, err = run([client, "ping"])
    text = (out or err).lower()
    if rc == 0 and "pong" in text:
        rep.ok("fail2ban.ping", "pong")
    else:
        rep.fail("fail2ban.ping", (out or err).strip() or f"exit {rc}")
        return

    rc, out, err = run([client, "status"])
    if rc != 0:
        rep.fail("fail2ban.status", (err or out).strip() or f"exit {rc}")
        return
    live_jails = set(parse_jail_list(out))
    jails = f2b.get("jails") or {}
    if not isinstance(jails, dict):
        rep.fail("fail2ban.jails", "expected.fail2ban.jails must be an object")
        return

    for jail_name, spec in jails.items():
        if not isinstance(spec, dict):
            continue
        if enabled(spec):
            if jail_name in live_jails:
                rep.ok(f"fail2ban.jail.{jail_name}", "loaded")
            else:
                rep.fail(
                    f"fail2ban.jail.{jail_name}",
                    f"not loaded (live: {', '.join(sorted(live_jails)) or 'none'})",
                )
                continue
            if jail_name == "sshd":
                check_sshd_jail(rep, expected, spec)
            elif jail_name == "nginx-limit-req":
                check_nginx_jail(rep, spec)
        else:
            if jail_name in live_jails:
                rep.fail(
                    f"fail2ban.jail.{jail_name}",
                    "loaded but expected enabled=false",
                )
            else:
                rep.skip(f"fail2ban.jail.{jail_name}", "enabled=false")

    want_action = str(f2b.get("banaction") or "").strip()
    if not want_action:
        rep.fail(
            "fail2ban.banaction",
            "expected banaction is empty (fail2ban parses action as '[port=...')",
        )
        return

    live_action = f2b_get("sshd", "banaction") if "sshd" in live_jails else None
    if live_action is None:
        jail_local = read_file("/etc/fail2ban/jail.local") or ""
        live_action = parse_key_values(jail_local).get("banaction")
    if live_action and want_action in live_action:
        rep.ok("fail2ban.banaction", live_action.splitlines()[-1].strip())
    else:
        rep.fail(
            "fail2ban.banaction",
            f"live {live_action or '(missing)'}, expected {want_action}",
        )


def check_sshd_jail(rep: Reporter, expected: dict, spec: dict) -> None:
    jail_text = read_file(SSHD_JAIL_FILE) or ""
    jail_kv = parse_key_values(jail_text)

    want_backend = str(spec.get("backend") or "systemd")
    live_backend = jail_kv.get("backend") or ""
    if live_backend == want_backend:
        rep.ok("fail2ban.sshd.backend", live_backend)
    else:
        rep.fail(
            "fail2ban.sshd.backend",
            f"{live_backend or '(missing)'} (need {want_backend}; "
            "file backend / auth.log is not the sshd source)",
        )

    want_match = str(spec.get("journalmatch") or "_SYSTEMD_UNIT=ssh.service")
    live_match = f2b_get("sshd", "journalmatch") or jail_kv.get("journalmatch") or ""

    def _norm_match(value: str) -> str:
        return re.sub(r"\s*=\s*", "=", " ".join(value.split()))

    if _norm_match(want_match) in _norm_match(live_match):
        rep.ok("fail2ban.sshd.journalmatch", want_match)
    else:
        rep.fail(
            "fail2ban.sshd.journalmatch",
            f"{live_match or '(missing)'} (need {want_match}; "
            "_COMM=sshd misses sshd-session on OpenSSH 9.8+)",
        )

    want_port = parse_port(spec.get("port"))
    if want_port is None:
        want_port = parse_port((expected.get("ssh") or {}).get("port"))
    live_port = parse_port(f2b_get("sshd", "port") or jail_kv.get("port"))
    sshd_parsed, _ = sshd_effective()
    sshd_port = parse_port((sshd_parsed or {}).get("port"))
    if want_port is not None and live_port == want_port:
        if sshd_port is not None and sshd_port != live_port:
            rep.fail(
                "fail2ban.sshd.port",
                f"jail {live_port} != sshd {sshd_port}",
            )
        else:
            rep.ok("fail2ban.sshd.port", str(live_port))
    else:
        rep.fail("fail2ban.sshd.port", f"jail {live_port}, expected {want_port}")

    rc, out, err = run(
        [
            "journalctl",
            "-u",
            "ssh.service",
            "-n",
            "1",
            "--no-pager",
            "-q",
            "-o",
            "cat",
        ]
    )
    if rc == 0 and (out or "").strip():
        rep.ok("fail2ban.sshd.journal", "ssh.service has entries")
    else:
        detail = (err or out).strip() or "no journal entries for ssh.service"
        rep.fail(
            "fail2ban.sshd.journal",
            f"{detail} (sshd jail reads journal, not /var/log/auth.log)",
        )


def check_nginx_jail(rep: Reporter, spec: dict) -> None:
    logpath = str(spec.get("logpath") or "").strip()
    if not logpath:
        live = f2b_get("nginx-limit-req", "logpath")
        logpath = (live or "").splitlines()[0].strip() if live else ""
    if not logpath:
        rep.fail("fail2ban.nginx.logpath", "logpath missing from snapshot and live jail")
        return
    if os.path.isfile(logpath):
        if os.access(logpath, os.R_OK):
            rep.ok("fail2ban.nginx.logpath", logpath)
        else:
            rep.fail("fail2ban.nginx.logpath", f"{logpath} exists but is not readable")
    else:
        rep.fail(
            "fail2ban.nginx.logpath",
            f"{logpath} missing (fail2ban will not start this jail)",
        )


def check_firewall(rep: Reporter, expected: dict) -> None:
    fw = expected.get("firewall") or {}
    if not enabled(fw, "manage"):
        rep.skip("ufw", "firewall.manage is false")
        return

    ufw = which("ufw", "/usr/sbin/ufw")
    if not ufw:
        rep.fail("ufw.binary", "ufw not found")
        return

    rc, out, err = run([ufw, "status"])
    text = out or err
    first = text.splitlines()[0] if text.strip() else ""
    if rc == 0 and "Status: active" in text:
        rep.ok("ufw.active", first)
    else:
        rep.fail("ufw.active", (text.strip() or f"exit {rc}"))
        return

    port = parse_port((expected.get("ssh") or {}).get("port"))
    if port is None:
        rep.skip("ufw.ssh-port", "ssh.port missing from snapshot")
        return
    pattern = re.compile(
        rf"(^|\s){port}/tcp(\s|\(|$).*(ALLOW|LIMIT)",
        re.IGNORECASE,
    )
    if any(pattern.search(line) for line in text.splitlines()):
        rep.ok("ufw.ssh-port", f"{port}/tcp allow or limit")
    else:
        rep.fail("ufw.ssh-port", f"no allow/limit rule for {port}/tcp")


def check_auditd(rep: Reporter, expected: dict) -> None:
    auditd = expected.get("auditd") or {}
    if not enabled(auditd):
        rep.skip("auditd", "auditd.enabled is false")
        return
    check_service_active(rep, "auditd.service", "auditd")


def check_unattended(rep: Reporter, expected: dict) -> None:
    uu = expected.get("unattended_upgrades") or {}
    if not enabled(uu):
        rep.skip("unattended-upgrades", "unattended_upgrades.enabled is false")
        return
    rc, out, err = run(["dpkg-query", "-W", "-f", "${Status}", "unattended-upgrades"])
    status = (out or "").strip()
    if rc == 0 and "install ok installed" in status:
        rep.ok("unattended-upgrades.package", "installed")
    else:
        rep.fail(
            "unattended-upgrades.package",
            status or (err or f"exit {rc}").strip(),
        )
    if os.path.isfile(UNATTENDED_AUTO):
        rep.ok("unattended-upgrades.auto", UNATTENDED_AUTO)
    else:
        rep.fail("unattended-upgrades.auto", f"{UNATTENDED_AUTO} missing")


def rkhunter_web_cmd() -> str | None:
    files = [RKHUNTER_CONF]
    files.extend(sorted(glob.glob(os.path.join(RKHUNTER_CONF_D, "*"))))
    value = None
    for path in files:
        text = read_file(path)
        if text is None:
            continue
        parsed = parse_key_values(text)
        if "web_cmd" in parsed:
            value = parsed["web_cmd"]
    return value


def check_rkhunter(rep: Reporter, expected: dict, do_update: bool) -> None:
    packages = expected.get("packages") or {}
    if not enabled(packages, "rkhunter"):
        rep.skip("rkhunter", "packages.rkhunter is false")
        return

    binary = which("rkhunter", "/usr/bin/rkhunter")
    if not binary:
        rep.fail("rkhunter.binary", "rkhunter not found")
        return
    rep.ok("rkhunter.binary", binary)

    web_cmd = rkhunter_web_cmd()
    if not web_cmd:
        rep.fail("rkhunter.web_cmd", "WEB_CMD not set")
    elif os.path.basename(web_cmd.rstrip("/")) == "false" or web_cmd == "/bin/false":
        rep.fail(
            "rkhunter.web_cmd",
            f"{web_cmd} (signature download disabled; see README Troubleshooting)",
        )
    else:
        rep.ok("rkhunter.web_cmd", web_cmd)

    if not do_update:
        rep.skip("rkhunter.update", "pass --rkhunter-update to run rkhunter --update")
        return

    rc, out, err = run([binary, "--update"], timeout=180)
    # Role treats rc >= 2 as failure; rc 1 is warning.
    if rc >= 2:
        detail = (err or out).strip().splitlines()
        tail = detail[-1] if detail else f"exit {rc}"
        rep.fail("rkhunter.update", tail)
    else:
        rep.ok("rkhunter.update", f"exit {rc}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Runtime smoke checks for brotherhugo.harden (uses expected.json).",
    )
    parser.add_argument(
        "--expected",
        default=DEFAULT_EXPECTED,
        help=f"sanitized snapshot path (default: {DEFAULT_EXPECTED})",
    )
    parser.add_argument(
        "--rkhunter-update",
        action="store_true",
        help="also run rkhunter --update (network; not part of the default smoke)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    expected = load_expected(args.expected)
    if _contains_secret_keys(expected):
        print(
            "FAIL  expected snapshot contains password or authorized_keys; "
            "refusing to continue"
        )
        return 1

    rep = Reporter()
    check_ssh(rep, expected)
    check_fail2ban(rep, expected)
    check_firewall(rep, expected)
    check_auditd(rep, expected)
    check_unattended(rep, expected)
    check_rkhunter(rep, expected, do_update=args.rkhunter_update)
    return rep.summary()


if __name__ == "__main__":
    sys.exit(main())
