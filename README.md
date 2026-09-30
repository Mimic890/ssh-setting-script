# ssh-setup

Interactive Bash script that hardens SSH on a fresh server and installs fail2ban.
You answer a few questions, read a summary, confirm, and the script does the rest.

- **Supported systems:** Ubuntu 24.04+ and Debian 12+ (systemd required)
- **Run as:** root
- **Result:** key-only SSH login (no passwords), custom port, modern crypto, fail2ban

> Always keep your current SSH session open while the script runs.
> The script is built so that you cannot lock yourself out (see [Safety](#safety-features)), but a spare session is the best insurance.

## Quick start

```bash
# Download, read it, then run it
curl -fsSL https://raw.githubusercontent.com/mimic890/ssh-setting-script/main/ssh-setup.sh -o ssh-setup.sh
less ssh-setup.sh
sudo bash ssh-setup.sh
```

Try it without changing anything:

```bash
sudo bash ssh-setup.sh --dry-run
```

You can also pipe it (`curl ... | sudo bash`). Questions are read from the terminal, so this works too,
but downloading and reading the script first is the better habit for a script that runs as root.

## What the script does, in order

1. **Preflight** - checks root, OS version, systemd, `sshd`, and detects the current SSH port(s) and your current IP.
2. **Questions** (each one is explained on screen, every question has a default in `[brackets]`):

   | # | Topic | What it decides |
   |---|-------|-----------------|
   | 1 | SSH port | New port. The script checks that it is free (not used by another program). Press Enter for a random free port. |
   | 2 | Login user | `root` by default (key-only). Any other name is created if missing; root login over SSH is then disabled. Optional passwordless `sudo` for a new user. |
   | 3 | SSH key | (1) paste your public key, or (2) generate an ed25519 pair on the server. See [Keys](#keys). |
   | 4 | Who may log in | `AllowUsers`: only the chosen user may log in. |
   | 5 | Brute-force limits | `MaxAuthTries`, `LoginGraceTime`, `MaxStartups`, keep-alive checks. |
   | 6 | Forwarding and extras | X11 forwarding, TCP forwarding (`no` / `local` / `yes`), agent forwarding, login banner. |
   | 7 | Firewall | Detects `ufw` / `firewalld` / custom rules and opens the new port, or tells you to do it. |
   | 8 | fail2ban | `maxretry`, `findtime`, `bantime`, recidive, whitelist. |

3. **Summary** - a plain-text list of everything that will be configured. You answer `y` / `N`.
   `N` (the default) changes nothing.
4. **Apply**, in two phases so you cannot get locked out:
   1. Back up `/etc/ssh`, create the user (if needed), install the key, write the config.
      SSH listens on the **old and the new port** at the same time.
   2. The script asks you to open a **second terminal** and log in on the new port.
      Type `yes` within 300 seconds. If you do not, the configuration is **rolled back automatically**.
   3. After `yes`, the old port is closed, then fail2ban is installed and configured.
5. **Final report** - key paths, firewall reminders, useful commands.

## SSH settings applied

The script writes one drop-in file, `/etc/ssh/sshd_config.d/00-ssh-setup.conf`, and does **not** edit your `sshd_config`.
The `00-` prefix matters: sshd uses the first value it sees, and this file is loaded before other drop-ins
(for example the cloud-init file on some Ubuntu images that turns passwords back on).

Always set (not asked):

| Setting | Value | Why |
|---------|-------|-----|
| `PasswordAuthentication` | `no` | Passwords can be guessed. Keys cannot. |
| `KbdInteractiveAuthentication` | `no` | Closes the "password through the back door" path. |
| `AuthenticationMethods` | `publickey` | Only keys are accepted. |
| `PermitEmptyPasswords` | `no` | Never allow accounts without password to log in by password. |
| `HostbasedAuthentication` | `no` | Trust by host name is not used. |
| `PermitUserEnvironment` | `no` | Users cannot inject environment variables into sshd. |
| `PermitRootLogin` | `prohibit-password` for root, `no` for another user | Root may only log in with a key. |
| `MaxStartups` | `10:30:60` | Above 10 unauthenticated connections 30% of new ones are dropped, at 60 all are. Limits floods. |
| `LogLevel` | `VERBOSE` | Logs the key fingerprint of every login. |
| `HostKey` / `HostKeyAlgorithms` | ed25519 only | Modern host key. Generated if missing. |
| `PubkeyAcceptedAlgorithms` | `ssh-ed25519`, `sk-ssh-ed25519@openssh.com` | Only modern keys. |
| `KexAlgorithms`, `Ciphers`, `MACs` | Modern list (sntrup761x25519 / curve25519, ChaCha20-Poly1305 / AES-GCM, HMAC-SHA2 ETM) | Old and weak algorithms are switched off. Names your OpenSSH does not know are filtered out automatically. |

Asked in the dialog:

| Setting | Default | Meaning |
|---------|---------|---------|
| `Port` | random free port | Where SSH listens. |
| `AllowUsers` | only the login user | Everyone else is refused. |
| `MaxAuthTries` | `3` | Login attempts per connection. |
| `LoginGraceTime` | `30` s | Time to finish logging in. |
| `ClientAliveInterval` / `ClientAliveCountMax` | `300` / `2` | Every 5 minutes the server checks the client; after 2 misses the connection is closed. Cleans up dead sessions. It does not disconnect idle-but-alive users. |
| `X11Forwarding` | `no` | Remote graphical windows. Rarely needed on servers. |
| `AllowTcpForwarding` | `no` | `no` = no tunnels, `local` = only `ssh -L`, `yes` = all. |
| `AllowAgentForwarding` | `no` | `ssh -A`. Risky if the server is compromised. |
| `Banner` | off | Text shown before login. |

Notes:

- Any active `Port` line in `sshd_config` or other drop-ins would add extra ports (sshd accumulates `Port` lines).
  The script comments them out (with a backup) so only your chosen port is used.
- **Ubuntu 24.04 uses systemd socket activation** (`ssh.socket`): the port in `sshd_config` is ignored there.
  The script detects this and also writes `/etc/systemd/system/ssh.socket.d/ssh-setup.conf`.
- Your `authorized_keys` may already contain other keys. They are kept; the new key is added.
  Remove keys you do not trust by editing `~/.ssh/authorized_keys`.
- Permissions are set correctly: `~/.ssh` is `700`, `authorized_keys` is `600`, private key `600`,
  public key `644`, and the home directory is made not group/world-writable (otherwise sshd ignores keys).

## Keys

Only **ed25519** keys are accepted (short, fast, strong). This also fits the "modern crypto only" settings.

1. **Paste a public key** - one line starting with `ssh-ed25519` (the content of `~/.ssh/id_ed25519.pub`
   on your PC; create one with `ssh-keygen -t ed25519`). The format is validated.
2. **Generate on the server** - creates `~/.ssh/ssh-setup_ed25519` (private) and `.pub` (public) for the login user.
   You can protect the key with a passphrase. Then choose:
   - **Keep the private key on the server** - the script shows you the path at the end.
   - **Show it once, then delete it** - the private key is printed on screen for you to copy, and after you
     confirm the new login works it is securely deleted from the server. The public key stays in `authorized_keys`.

   A private key that lives on the server is a weaker setup than a key that only lives on your PC.
   Prefer option 1, or delete the generated private key after copying it.

## Firewall

- **ufw** or **firewalld** active: the script offers to open the new TCP port for you.
- Custom **iptables/nftables** rules with a default DROP policy: the script cannot edit them safely and
  prints, in red, that you must open the port yourself.
- If you decline automatic opening, the exact command is printed in red at the end.
- The old port is **not** closed in the firewall automatically. The script prints the command.
- If your hosting provider has its own firewall or security group (most cloud providers do),
  the script cannot see it. Open the new port there too.

## fail2ban

Installed with `python3-systemd` (needed to read the journal; Debian 12 has no `/var/log/auth.log` by default).
Configuration goes to `/etc/fail2ban/jail.d/ssh-setup.local`.

| Jail | Purpose | Defaults |
|------|---------|----------|
| `sshd` | Bans IPs with failed logins (`aggressive` filter mode: also catches connections dropped before login). Uses your new SSH port. | `maxretry=3`, `findtime=10m`, `bantime=1h` |
| `recidive` | Bans repeat offenders. | 3 bans in 1 day -> 1 week (optional) |
| `ssh-setup-blacklist` | Permanent manual bans on **all** ports. | managed with `--f2b-blacklist-*` |

> With `aggressive` mode, a client that offers many keys from its agent can hit the limit and get banned.
> Use `ssh -o IdentitiesOnly=yes -i <key> ...` or whitelist your IP (the script offers to whitelist your current IP).

### Managing fail2ban afterwards

```bash
sudo bash ssh-setup.sh --f2b-status                 # jails, banned IPs, whitelist, blacklist
sudo bash ssh-setup.sh --f2b-unban-all              # remove all current bans
sudo bash ssh-setup.sh --f2b-unban 203.0.113.7      # unban one IP

sudo bash ssh-setup.sh --f2b-whitelist-add 203.0.113.0/24   # never ban (IP or CIDR)
sudo bash ssh-setup.sh --f2b-whitelist-del 203.0.113.0/24
sudo bash ssh-setup.sh --f2b-whitelist-list

sudo bash ssh-setup.sh --f2b-blacklist-add 198.51.100.9     # ban forever on all ports
sudo bash ssh-setup.sh --f2b-blacklist-del 198.51.100.9
sudo bash ssh-setup.sh --f2b-blacklist-list

sudo bash ssh-setup.sh --f2b-sync                   # reload fail2ban, re-apply the blacklist
```

The lists live in `/etc/ssh-setup/whitelist.list` and `/etc/ssh-setup/blacklist.list`.
Permanent bans are stored in the fail2ban database (its purge age is raised to 10 years by the script).
If bans ever get lost, `--f2b-sync` re-applies the blacklist.

## Safety features

- **Backup:** `/etc/ssh` is copied to `/var/lib/ssh-setup/backup-<date>/` before any change.
- **Validation:** the config is checked with `sshd -t`, and the effective result is checked with `sshd -T`
  (password login must really be off, even if some other file tries to override it).
- **Two-phase port change:** old and new ports work together until you confirm the new login.
- **Automatic rollback:** a systemd timer (`ssh-setup-watchdog`) restores the old configuration after 300 seconds
  if you do not confirm. It also fires if your connection drops while the script runs.
- **Manual rollback:** `sudo bash ssh-setup.sh --rollback` restores the previous SSH configuration.
  (It does not remove the added public key, the firewall rule or fail2ban.)
- **Nothing happens without your confirmation** - the summary prompt defaults to `N`.

## Files

| Path | Purpose |
|------|---------|
| `/etc/ssh/sshd_config.d/00-ssh-setup.conf` | SSH settings written by the script |
| `/etc/systemd/system/ssh.socket.d/ssh-setup.conf` | Port for socket-activated SSH (Ubuntu) |
| `/etc/fail2ban/jail.d/ssh-setup.local`, `ssh-setup-whitelist.local` | fail2ban jails and whitelist |
| `/etc/fail2ban/filter.d/ssh-setup-blacklist.conf` | Filter for the manual blacklist jail |
| `/etc/ssh-setup/` | Whitelist and blacklist |
| `/var/lib/ssh-setup/` | Backups and the generated `rollback.sh` |
| `/var/log/ssh-setup.log` | What the script did |

## Options

```
sudo bash ssh-setup.sh [--dry-run | --rollback | --f2b-* | --help | --version]
```

Environment variable `SSH_SETUP_INPUT` can point to a file with prepared answers (one per line) instead of the terminal.
It is meant for testing.

## Not included (yet)

Two-factor authentication, general server hardening (kernel settings, automatic updates, full firewall setup).
The current scope is SSH + fail2ban only.

## License

See [LICENSE](LICENSE).
