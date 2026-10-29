# agent-box-hardening

Run Chrome **with its sandbox on** on an AI agent's cloud VM, and keep it that
way when the platform quietly puts its own files back.

Agent VMs that drive a real desktop browser usually ship a launcher that starts
Chrome with `--no-sandbox`, as the same user the agent runs as, with the agent's
whole environment, on an X display that accepts any local client (`Xvfb -ac`).
The usual advice is "it's a throwaway VM, `--no-sandbox` is fine". It isn't
great: the browser loads arbitrary web content, and without the sandbox one
renderer bug gives an attacker the agent user, its tokens, its workspace and
every other display.

Fixing it once is easy. Keeping it fixed is the hard part: a platform redeploy,
image update or VM migration can silently revert the launcher (or hand you a
brand-new VM with none of your changes), and the next browser start is
unsandboxed again. This repository is the tooling that came out of dealing
with that:

* `box-hardening.sh` checks, applies and re-verifies the hardening, idempotently
* `box-fastfix-watch.sh` re-hardens a reverted file within seconds
* `box-drift.py` records what changed on the VM, and when
* a **known-hash allowlist**: files are only patched when their exact
  version is known, and unknown versions wait for a human

## What it does

| Section | What stays true |
|---|---|
| 1 Browser user | Chrome runs as a dedicated unprivileged user `chrome`, sandbox on, with a clean environment. The agent may switch to that user (and only that user) through one sudo rule. The launcher must be a known hardened version. |
| 2A Firewall | nftables: processes of the browser user may only reach the loopback ports you allow (e.g. an egress proxy); optionally public addresses; private ranges and everything else are dropped. |
| 2B X cookie auth | Xvfb displays use MIT-MAGIC-COOKIE authentication instead of `-ac`. The agent gets cookies for all displays; the browser user only for its own. |
| 2C Permissions | Workspace 750, nothing world-writable in it, configured private dirs 700, configured sockets with fixed owner/mode. |
| Verify | Behavioural re-tests: the browser runs as `chrome`, without `--no-sandbox`, renderers under seccomp; the browser user is refused by the firewall and by X displays that aren't its own; the agent still works. |

Every item is *check → fix only if drifted → re-check*, and printed as a table:
`PASS`, `FIXED`, `FAIL`, `WARN` or `SKIP`.

## Threat model (brief)

In scope: a compromised or malicious **web page** (renderer exploit, sandbox
escape attempt, drive-by) and anything that ends up running as the browser
user. Goals: the sandbox is on; if it is broken, the attacker is a user with
no access to the agent's files, environment, credentials, other displays or
private networks.

Also in scope: **configuration drift** from the platform itself. Redeploys
replace files; the tooling detects that within seconds (watched files) or an
hour (everything else) and either restores the known hardened version or
raises an alert.

Out of scope: the platform operator, the hypervisor, the agent itself (it can
switch to the browser user by design), and kernel exploits. This hardens one
layer of a VM you do not fully control; it is not a replacement for the
platform's own isolation.

## How it works

**Known-hash allowlist.** Each managed file has a *chain* per known platform
version in `chains/<set>/<version>/`:

```
orig.sha256        hash of the stock file as the platform ships it
sandboxed.sha256   (optional) stock minus the --no-sandbox line
hardened.sha256    hash of our hardened version
patch.diff         stock (or sandboxed) -> hardened
```

If the current file is a known hardened hash: PASS. If it is a known stock or
sandbox-only version: apply that chain's patch to a copy, verify that the
result has the hardened hash, and only then install it (with a backup). Any
other hash is **refused**: the tool never patches a file it has not seen, so a
new platform version cannot be half-patched into something broken or unsafe.
A human reviews the new file, creates a chain with `tools/make-chain.sh`, and
approves the new `SHA256SUMS` (below).

**Fast fix.** `box-fastfix-watch.sh` (a small root daemon) hashes only the
managed files every 2 s, waking sooner via `inotifywait` if it is installed.
On a non-hardened hash it runs `box-hardening.sh --watch --only <section>`,
which re-hardens known versions and refuses unknown ones. Failures back off
(2, 4, 8, 15, 30 s); a refused unknown version is re-checked every 10 minutes
and reported once.

**Fresh-instance detection.** `--detect-fresh` compares the VM against a
baseline kept on persistent disk and tells a resume (0) from a reboot (30), a
same-VM-with-state-missing (31) and a brand-new VM (40). Strong signals are a
marker file on the root filesystem and `/etc/machine-id`; weaker ones (browser
user, VPN state, hostname, nft table) only count in combination. The baseline
is parsed as `key=value`, never sourced. After a rebuild, `--rebaseline`
records the new VM as the known one.

**Drift log.** `box-drift.py` snapshots configured paths, process roles,
version commands and the package list into SQLite (as the agent user, never
root) and turns each difference into a notification until marked reported.
Hashes are labelled from the chains, so a revert reads
`HARDENED browser-launcher v3 -> STOCK browser-launcher v3`.

**X cookies.** The hardened Xvfb wrapper replaces `-ac` with `-auth`, creating
a fresh cookie with `mcookie` (passed to `xauth` on stdin, never on a command
line, never logged), stores it 600 root-only and merges it into the agent's
`~/.Xauthority`. If anything fails it keeps `-ac` and logs a warning rather than
leaving the agent without a display. Existing displays switch over the next
time they restart; `--apply --restart-displays` can restart them behind a
dead-man's switch that rolls back unless a canary proves the new display
works.

## Quick start

Requirements: bash, coreutils, `patch`, `diff`, `nft`, `xauth`, `mcookie`,
`flock`, python3 (drift log), `sudo`. Optional: `inotifywait`
(inotify-tools), `xdpyinfo`, `shellcheck`.

```sh
# 1. test (no root, temp files only)
tests/run-all.sh

# 2. install as a root-owned tree (the watcher refuses anything else)
sudo install -d -o root -g root -m 755 /opt/box-hardening /etc/box-hardening
sudo cp -r . /opt/box-hardening && sudo chown -R root:root /opt/box-hardening
sudo install -o root -g root -m 644 config/box-hardening.conf.example /etc/box-hardening/box-hardening.conf
sudo cp -r examples/chains /etc/box-hardening/chains   # replace with chains for YOUR files

# 3. edit /etc/box-hardening/box-hardening.conf: users, TARGETS, ports, paths
# 4. look first, then fix
sudo /opt/box-hardening/box-hardening.sh --check
sudo /opt/box-hardening/box-hardening.sh --apply
sudo /opt/box-hardening/box-hardening.sh --rebaseline

# 5. keep it fixed
sudo cp systemd/*.service systemd/*.timer /etc/systemd/system/
sudo systemctl enable --now box-hardening.timer box-fastfix.service
```

The example chains are for the sample files in `examples/stock/` only. For a
real VM, copy the platform's launcher and X wrapper, write your hardened
versions (see `examples/README.md`), and build chains:

```sh
tools/make-chain.sh --strip-no-sandbox /etc/box-hardening/chains browser-launcher v1 \
    stock-launcher hardened-launcher
tools/make-chain.sh /etc/box-hardening/chains xvfb-wrapper v1 stock-wrapper hardened-wrapper
```

`make-chain.sh` refuses a hardened file that still contains `--no-sandbox` and
a patch that does not reproduce the hardened file byte for byte.

Without systemd, run `examples/hourly.sh` from cron and
`box-fastfix-watch.sh --start` at boot (`--ensure-running` is idempotent).

## Approving hashes (the human step)

Root runs this code every hour and every few seconds, so a change to it, or a new
chain, should be something a person looked at. The workflow:

1. Review the change: `git diff`, and for a new platform version the stock
   file and `patch.diff`.
2. `tests/run-all.sh`, then `tools/update-sums.sh`. It rewrites `SHA256SUMS` and
   prints one hash.
3. Record that hash on the VM, root-owned:
   `echo <hash> | sudo tee /etc/box-hardening/approved-sums.sha256`
4. `tools/verify-sums.sh /opt/box-hardening`. `examples/hourly.sh` runs it first
   and does nothing (except report `needs-attention`) if the installed tree
   does not match the approved hash, or if any unlisted script appears.

Nothing in the tooling approves a hash by itself. An unknown platform file stays
refused, and is reported, until someone completes these steps.

## Modes

```
box-hardening.sh [--config FILE] [--check | --apply | --watch] [--only 1,2A,2B,2C,V]
box-hardening.sh --apply --restart-displays
box-hardening.sh --detect-fresh | --rebaseline | --list-targets | --selftest
box-fastfix-watch.sh --start | --stop | --status | --ensure-running | --once | --selftest
box-drift.py [--label L] | --add-event ... | --list-unreported | --mark-reported ID|all | --history PATH | --selftest
```

`--watch` is the unattended mode. It applies only safe fixes and never restarts
displays. It ends with `RESULT: clean|fixed|needs-attention` and exits 0, 10 or 20.

## Limitations

* **The agent can become the browser user.** That is what lets the launcher
  start Chrome as `chrome`. The protection points the other way: the browser
  cannot reach the agent. The sudo rule allows only `chrome`, never root. If your
  launcher is started by a root supervisor, switch with `setpriv`/`runuser` there
  instead and set `BROWSER_SUDOERS=""`.
* `sudo -u chrome` in the launcher means the browser's parent chain passes
  through sudo. Starting it from a root supervisor with `setpriv` gives a
  cleaner process tree and needs no sudo rule, but you have to control that supervisor.
* **Detection is not prevention.** Between a revert and the next scan (about 2 s
  for watched files, up to an hour for the rest), the stock file is live.
  A browser started in that window runs unhardened until it restarts.
* Unknown platform versions are refused, not fixed. Until a human adds a chain,
  the file stays stock and the run reports `needs-attention`.
* Existing X displays keep `-ac` until they restart. Restarting them is opt-in.
* The firewall matches on UID. Anything running as the browser user is
  filtered, anything else is not. It does not filter by destination name,
  so use an egress proxy on an allowed loopback port for that.
* The tooling trusts the kernel, root and the platform. It hardens one
  user-level layer and cannot defend against the VM's operator.
* Written for a Debian-based image. Paths and user names are configurable,
  but other distributions may need tweaks. The systemd units are examples:
  many agent VMs have no systemd, so use cron or the platform's scheduler there.

## Layout

See [`REBUILD.md`](REBUILD.md) for rebuilding a fresh VM from scratch, and
`examples/README.md` for how the sample launcher and X wrapper are hardened.

## License

MIT, see [LICENSE](LICENSE).
