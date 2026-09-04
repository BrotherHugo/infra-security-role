# harden

Universal Ansible role for hardening Ubuntu/Debian hosts.

All settings are defined under the `harden:` root in `group_vars` / `host_vars` (or role `defaults`). Secrets — via vault, `--extra-vars`, or environment variables (see `admin_user`).

**Platforms:** Ubuntu 22.04+, Debian 12+ (see `meta/main.yml`).

**Dependencies:** collections `community.general`, `ansible.posix`.

---

## Installation

The role is distributed via git (not galaxy.ansible.com). In the consumer's `requirements.yaml`:

```yaml
- name: brotherhugo.harden
  src: git+https://github.com/BrotherHugo/infra-security-role.git
  version: v0.1.0
```

```bash
ansible-galaxy install -r requirements.yaml
```

In the playbook, invoke the role as `brotherhugo.harden`:

```yaml
roles:
  - brotherhugo.harden
```

If `harden:` is split across `group_vars` and `host_vars` (overlay inventory), the consumer's `ansible.cfg` must set `hash_behaviour = merge`. Without merge, the `harden` key in `host_vars` replaces the entire dictionary from `group_vars`.

---

## Quick start

```yaml
# inventory/group_vars/webservers.yaml
harden:
  ssh:
    port: 22
    permit_root_login: false
  firewall:
    manage: true
    rules:
      - rule: allow
        port: "22"
        proto: tcp
        comment: SSH
      - rule: allow
        port: "443"
        proto: tcp
        comment: HTTPS
  fail2ban:
    jails:
      nginx-limit-req:
        enabled: true
```

---

## Parameter reference

Below is the full role contract. Default values are in `defaults/main.yml`.

### `harden.ssh`

Controls the `sshd` drop-in and the fail2ban `sshd` jail port. **The role does not create a UFW rule for SSH** — add it explicitly in `harden.firewall.rules`.

| Parameter | Type | Default | Description |
|----------|-----|--------------|----------|
| `enabled` | bool | `true` | Enable the SSH block (drop-in + `sshd -t` validation). |
| `port` | int | `22` | sshd port (`Port` in drop-in) and `port` in fail2ban jail `sshd`. When changing, set `ansible_port` in inventory. |
| `permit_root_login` | bool or str | `false` | `PermitRootLogin`. Accepts `true`/`false` or `'yes'`/`'no'`. |
| `password_authentication` | bool or str | `false` | `PasswordAuthentication`. |
| `pubkey_authentication` | bool | `true` | `PubkeyAuthentication`. |
| `max_auth_tries` | int | `3` | `MaxAuthTries`. |
| `allow_tcp_forwarding` | bool | `false` | `AllowTcpForwarding`. |
| `allow_agent_forwarding` | bool | `false` | `AllowAgentForwarding`. |
| `x11_forwarding` | bool | `false` | `X11Forwarding`. |
| `client_alive_interval` | int | `300` | `ClientAliveInterval` (seconds). |
| `client_alive_count_max` | int | `2` | `ClientAliveCountMax`. |
| `login_grace_time` | int | `30` | `LoginGraceTime` (seconds). |
| `use_dns` | bool | `false` | `UseDNS`. |
| `dropin_path` | str | `/etc/ssh/sshd_config.d/99-harden.conf` | Path to the drop-in file with hardening settings. |
| `manage_main_config` | bool | `true` | Replace `/etc/ssh/sshd_config` with a minimal template containing `Include /etc/ssh/sshd_config.d/*.conf`. If `false` — only adds the `Include` line if missing. |

**Files on the server:** `harden.ssh.dropin_path`, when `manage_main_config: true` — `/etc/ssh/sshd_config`.

---

### `harden.firewall`

UFW: default-deny incoming, rules from inventory. Runs only when `manage: true`.

| Parameter | Type | Default | Description |
|----------|-----|--------------|----------|
| `manage` | bool | `false` | Manage UFW from the role. |
| `force_reset` | bool | `false` | `ufw --force reset` before applying rules. **Dangerous:** wipes manual rules. |
| `default_incoming` | str | `deny` | Incoming policy: `deny`, `allow`, or `reject`. |
| `default_outgoing` | str | `allow` | Outgoing policy. |
| `rules` | list | `[]` | Primary rule list (see schema below). |
| `extra_rules` | list | `[]` | Additional rules; merged with `rules` on apply. Useful for host-specific ports without duplicating group rules. |

**Schema for `rules` / `extra_rules` items:**

| Field | Required | Description |
|------|-------------|----------|
| `rule` | no (default `allow`) | `allow`, `deny`, or `reject`. |
| `port` | yes | Port or range (string, e.g. `"443"`). |
| `proto` | yes | `tcp` or `udp`. |
| `from_ip` | no | Restrict source (e.g. `"203.0.113.10"`). |
| `comment` | no | UFW comment. |

Apply order: install UFW → (optional reset) → loop over `rules + extra_rules` → default policies → `ufw enable`.

**SSH in UFW** — only an explicit rule with the same port number as `harden.ssh.port`:

```yaml
harden:
  ssh:
    port: 22
  firewall:
    rules:
      - rule: allow
        port: "22"
        proto: tcp
        comment: SSH
```

Do not use `{{ harden.ssh.port }}` inside `harden.firewall.rules` — it is part of the `harden` dict and causes recursive templating in Ansible.

**Inventory merge:** with `hash_behaviour = merge` in `ansible.cfg`, `host_vars` with `harden.ssh` extend `group_vars` (`firewall`, `fail2ban`, etc.) without replacing the entire `harden`.

---

### `harden.fail2ban`

| Parameter | Type | Default | Description |
|----------|-----|--------------|----------|
| `enabled` | bool | `true` | Install (via `packages`) and configure fail2ban. |

#### `harden.fail2ban.jails.sshd`

| Parameter | Type | Default | Description |
|----------|-----|--------------|----------|
| `enabled` | bool | `true` | Jail `sshd` in `/etc/fail2ban/jail.d/sshd.local`. When `false` — file is removed. |
| `maxretry` | int | `3` | Threshold before ban. |
| `bantime` | int | `86400` | Ban duration (seconds). |
| `findtime` | int | `600` | Attempt counting window (seconds). |

Jail port comes from `harden.ssh.port`. Log: `/var/log/auth.log`.

#### `harden.fail2ban.jails.nginx-limit-req`

| Parameter | Type | Default | Description |
|----------|-----|--------------|----------|
| `enabled` | bool | `false` | Jail for nginx rate-limit. When `false` — jail and filter are removed from disk. |
| `logpath` | str | `/var/log/nginx/access.log` | Log to monitor. **Requires nginx installed and the log file present.** |
| `maxretry` | int | `10` | Threshold before ban. |
| `bantime` | int | `7200` | Ban duration (seconds). |
| `findtime` | int | `600` | Counting window (seconds). |

**Files:** `/etc/fail2ban/jail.local`, `/etc/fail2ban/jail.d/*.local`, `/etc/fail2ban/filter.d/nginx-limit-req.conf` (when jail is enabled).

After configuration, the `fail2ban` service is forced to `started` + `enabled`.

---

### `harden.auditd`

| Parameter | Type | Default | Description |
|----------|-----|--------------|----------|
| `enabled` | bool | `true` | Install auditd, template `auditd.conf`, FIM rules, start service. |
| `fim_paths` | list | see defaults | Base path list for file integrity monitoring (`-w` in `audit.rules`). |
| `fim_paths_extra` | list | `[]` | Additional paths (merged with `fim_paths`). |

**Schema for `fim_paths` / `fim_paths_extra` items:**

| Field | Description |
|------|----------|
| `path` | Absolute path to a file. |
| `permissions` | Audit permissions, e.g. `wa` (write, attribute change). |
| `key` | Event label (`ausearch -k <key>`). |

---

### `harden.unattended_upgrades`

| Parameter | Type | Default | Description |
|----------|-----|--------------|----------|
| `enabled` | bool | `true` | Package `unattended-upgrades` and configs in `/etc/apt/apt.conf.d/`. |
| `automatic_reboot` | bool | `true` | `Unattended-Upgrade::Automatic-Reboot`. |
| `automatic_reboot_time` | str | `"02:00"` | Reboot time (`HH:MM`). |
| `security_only` | bool | `true` | Only `-security` (if `false` — also updates). |

---

### `harden.sysctl`

| Parameter | Type | Default | Description |
|----------|-----|--------------|----------|
| `enabled` | bool | `true` | Apply parameters via `sysctl` and write to `/etc/sysctl.d/99-harden.conf`. |
| `parameters` | list | see defaults | List of `{ name, value }` — IPv4/IPv6 network hardening parameters. |

Full list of default `name` values — in `defaults/main.yml` (rp_filter, syncookies, redirects, martians, etc.).

---

### `harden.packages`

Package installation (no cron/report collection setup for scanners).

| Parameter | Type | Default | Package |
|----------|-----|--------------|-------|
| `fail2ban` | bool | `true` | `fail2ban` |
| `auditd` | bool | `true` | `auditd` |
| `apparmor_utils` | bool | `true` | `apparmor-utils` |
| `lynis` | bool | `true` | `lynis` |
| `rkhunter` | bool | `true` | `rkhunter` (install only + `rkhunter --update` on first run) |
| `chkrootkit` | bool | `true` | `chkrootkit` (install only) |

The role **removes** legacy files `/etc/cron.daily/rkhunter`, `/etc/cron.daily/chkrootkit`, and related logrotate configs if they remain from older role versions.

---

### `harden.admin_user`

Bootstrap a local administrator. **Disabled** by default (`enabled: false`).

| Parameter | Type | Default | Description |
|----------|-----|--------------|----------|
| `enabled` | bool | `false` | Create user, sudoers, `.ssh/authorized_keys`. |
| `name` | str | `admin` | Username. |
| `groups` | list | `[sudo]` | Additional groups (besides primary). |
| `sudo_nopasswd` | bool | `false` | `NOPASSWD` in sudoers. |
| `password` | str / null | `null` | Hash or plaintext for the `user` module. Alternative: env `HARDEN_ADMIN_PASSWORD`. Without password — account with no password login (`!`). |
| `authorized_keys` | list | `[]` | List of public key strings. |
| `authorized_keys_file` | str / null | `null` | Path to keys file on control node. Lower priority than `authorized_keys`. |

If `authorized_keys` and `authorized_keys_file` are empty — env `HARDEN_ADMIN_SSH_PUBLIC_KEY` is used (line by line).

**Do not commit secrets to git.** Use vault or environment variables when running the playbook.

---

### `harden.cron_jobs`

Generic cron jobs (not tied to security scanners).

| Item field | Required | Description |
|---------------|-------------|----------|
| `name` | yes | Job name (`cron` module `name`). |
| `minute` | yes | Minute. |
| `hour` | yes | Hour. |
| `job` | yes | Command. |
| `user` | no | User (default `root`). |
| `state` | no | `present` or `absent` (default `present`). |

Empty list `[]` — block creates no jobs.

---

### `harden.logrotate`

Additional snippet files in `/etc/logrotate.d/`.

| Item field | Required | Description |
|---------------|-------------|----------|
| `name` | yes | Filename in `/etc/logrotate.d/` (no path). |
| `path` | yes | Log file path inside the logrotate block. |

Rotation: daily, 30 files, compress. Empty list — nothing is created.

---

## Tags

| Tag | Block |
|-----|------|
| `harden` | Entire role |
| `harden-firewall` | UFW |
| `harden-admin` | Admin user |
| `harden-ssh` | SSH drop-in |
| `harden-packages` | Package installation |
| `harden-sysctl` | sysctl |
| `harden-auditd` | auditd |
| `harden-fail2ban` | fail2ban |
| `harden-updates` | unattended-upgrades |
| `harden-cron` | cron_jobs |
| `harden-logrotate` | logrotate |

Example: `ansible-playbook site.yml --tags harden-fail2ban`.

---

## Custom SSH port

```yaml
# inventory/host_vars/myhost.yaml
ansible_port: 2222

harden:
  ssh:
    port: 2222
  firewall:
    manage: true
    rules:
      - rule: allow
        port: "2222"
        proto: tcp
        comment: SSH
```

`harden.ssh.port` → sshd + fail2ban. UFW — the same port explicitly in `firewall.rules` (set both fields to the same value).

---

## Environment variables

| Variable | Used in |
|------------|----------------|
| `HARDEN_ADMIN_PASSWORD` | `harden.admin_user.password`, if not set in inventory |
| `HARDEN_ADMIN_SSH_PUBLIC_KEY` | `harden.admin_user.authorized_keys`, if list and file are empty |

---

## Limitations and notes

- The role targets **Debian/Ubuntu** (`apt`). Other distributions are not supported.
- Do not enable fail2ban jail `nginx-limit-req` on hosts without nginx — fail2ban will not start.
- rkhunter/chkrootkit: install-only; collection and alerts are outside the role.
- Changing the SSH port does not update UFW rules automatically, be sure to sync them in your config.
- `harden.firewall.force_reset: true` — use only deliberately, with a backup of rules.
