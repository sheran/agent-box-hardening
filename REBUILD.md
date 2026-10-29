# Rebuilding a fresh VM

Use this when `--detect-fresh` exits 40 ("fresh instance"), meaning the
platform gave you a new VM, or when you set up a new one. The hourly job does
steps 3 to 6 by itself when it sees exit 40. This page is the manual version,
and the checklist for when the automatic run reports `needs-attention`.

Assumptions: the workspace (or another persistent disk) survives a redeploy and
the root filesystem does not. Keep this repository, the drift database and the
instance baseline on the persistent disk, and keep your configuration in this
repository or somewhere else you can restore from.

## 1. Look before you change anything

```sh
cd /path/to/agent-box-hardening
tests/run-all.sh                        # the tooling itself still works here
sudo ./box-hardening.sh --detect-fresh  # 40 = fresh; the reasons are printed
sudo ./box-hardening.sh --check         # what is stock, what is unknown
./box-drift.sh --label rebuild-pre      # record the new VM as it was delivered
```

If `--check` reports **"not a known version"** for a managed file, the
platform has shipped a new launcher or wrapper. Do not force it. Go to step 2.

## 2. New platform versions (only if step 1 reported unknown hashes)

```sh
cp /opt/agent/launchers/browser /tmp/stock-launcher           # your TARGETS path
diff -u <previous stock copy> /tmp/stock-launcher             # what did they change?
# write the hardened version (examples/README.md), then:
tools/make-chain.sh --strip-no-sandbox chains browser-launcher v2 /tmp/stock-launcher /tmp/hardened-launcher
tests/run-all.sh && tools/update-sums.sh                      # prints the hash to approve
```

A human approves the printed hash (README, "Approving hashes").

## 3. Install the root-owned copy

```sh
sudo install -d -o root -g root -m 755 /opt/box-hardening /etc/box-hardening
sudo cp -r . /opt/box-hardening && sudo chown -R root:root /opt/box-hardening
sudo install -o root -g root -m 644 config/box-hardening.conf /etc/box-hardening/box-hardening.conf
sudo rm -rf /etc/box-hardening/chains && sudo cp -r chains /etc/box-hardening/chains
echo <approved hash> | sudo tee /etc/box-hardening/approved-sums.sha256
sudo /opt/box-hardening/tools/verify-sums.sh /opt/box-hardening
```

## 4. Apply

```sh
sudo /opt/box-hardening/box-hardening.sh --apply
```

This creates the browser user, the sudo rule, the nft table, the X cookie
wrapper and the permission fixes, then re-verifies each one. Every line should
be `PASS` or `FIXED`. A `FAIL` names the file or setting, so fix it and run again.
The command is idempotent.

## 5. Displays and the browser

Displays that were started before the wrapper was hardened still use `-ac`
(reported as a `WARN`). Either let the platform restart them, or:

```sh
sudo /opt/box-hardening/box-hardening.sh --apply --restart-displays
```

Each display gets a dead-man's switch. If the restarted display does not pass
the end-to-end check (the agent connects with its cookie, nobody connects
without one), the canary file is never written. After `DMS_SECONDS` the rollback
script then creates `noauth-N`, removes the cookie and kills that Xvfb, so the
supervisor brings it back with `-ac`. Then restart the browser through the
hardened launcher and check:

```sh
sudo /opt/box-hardening/box-hardening.sh --check --only V
```

## 6. Record the new VM and keep it hardened

```sh
sudo /opt/box-hardening/box-hardening.sh --rebaseline     # this VM is now "known"
sudo /opt/box-hardening/box-fastfix-watch.sh --ensure-running
./box-drift.sh --label rebuild-post
# systemd: systemctl enable --now box-hardening.timer box-fastfix.service
# otherwise: schedule examples/hourly.sh hourly with your platform's scheduler
```

## 7. Confirm

* `sudo /opt/box-hardening/box-hardening.sh --watch` prints `RESULT: clean`
* `sudo /opt/box-hardening/box-hardening.sh --detect-fresh` exits 0
* `./box-drift.sh --list-unreported` shows the rebuild. Review it, then
  run `--mark-reported all`
* in the browser, `chrome://sandbox` shows every layer on

## If something goes wrong

* **The agent lost its display.** `xauth list` as the agent should show the
  display. If it does not, create `${XVFB_NOAUTH_DIR}/noauth-N` (as root) and
  restart that display. It comes back with `-ac`. Read `XVFB_AUTH_LOG` to find the cause.
* **The browser does not start.** Run the launcher by hand as the agent and read the
  error. `BROWSER_AS_AGENT=1` starts it the old way for one launch, so you can tell
  whether the user switch is the problem. Do not leave that set.
* **The fast-fix watcher keeps reporting "refused".** `/opt/box-hardening`, or a
  directory above it, is writable by a non-root user, so the watcher will not run
  the scripts as root. Fix the ownership.
* Backups of every file the tool replaced are in `BACKUP_DIR` (default
  `/var/backups/box-hardening`), and actions are logged in `LOG_FILE`.
