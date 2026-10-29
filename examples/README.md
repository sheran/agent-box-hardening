# Examples

Everything here was written for this repository to show the pattern; none of
it is a copy of any platform's files. The selftests use these samples, so the
chains in `chains/` hash these exact files. Regenerate the chains with
`tools/make-chain.sh` if you change a sample.

| File | Purpose |
|---|---|
| `stock/browser-launcher.stock` | A typical "stock" agent launcher: Chrome as the agent user, `--no-sandbox`, full environment. |
| `stock/browser-launcher.hardened` | The same launcher, sandbox flag removed, switched to the `chrome` user with `sudo -n -u chrome`, clean `env -i` environment, its own profile and runtime dir. |
| `stock/xvfb-wrapper.stock` | A typical Xvfb wrapper that starts every display with `-ac` (no access control). |
| `stock/xvfb-cookie-block.sh` | The block inserted before `exec Xvfb` to switch a display to cookie auth, fail-safe. |
| `stock/xvfb-wrapper.hardened` | Stock wrapper plus that block. |
| `chains/*/example-v1/` | Allowlist entries (hashes + patch) for the samples above. |
| `hourly.sh` | One scheduled pass: verify approved sums, drift snapshot, detect fresh VM, apply or watch, drift snapshot, ensure the watcher runs. |
| `sudoers.agent-browser` | The one sudo rule Section 1 installs: agent may become `chrome`, never root. |

## Hardening a real launcher

1. Copy the platform's launcher off the VM (`stock`), and keep it unchanged.
2. Write `hardened`:
   * delete `--no-sandbox` (and `--disable-setuid-sandbox`, `--single-process`
     or `--no-zygote` if present)
   * start the browser as the browser user, either `sudo -n -u chrome -g chrome --`
     from the agent, or `setpriv`/`runuser` from a root supervisor
   * `env -i` with only what the browser needs: `HOME`, `PATH`, `DISPLAY`,
     `XAUTHORITY` pointing at the browser user's own cookie file, `LANG`, and a
     private `XDG_RUNTIME_DIR`. No tokens, no agent sockets.
   * a profile directory inside the browser user's home
   * keep the remote-debugging port only if the agent needs it. The firewall
     does not restrict loopback *into* the browser.
3. `tools/make-chain.sh --strip-no-sandbox CHAINS browser-launcher v1 stock hardened`
4. Test: `box-hardening.sh --check --only 1,V`, start the browser, and check
   that `chrome://sandbox` shows every layer on.
5. When the platform ships a new launcher, the check fails with "not a known
   version". Repeat from step 1 with `v2`, keeping `v1` for VMs that still
   have it.

## Hardening the X wrapper

Insert `xvfb-cookie-block.sh` before the wrapper's final `exec Xvfb "$@"`, set
its `_xa_*` parameters to match your config (`AGENT_USER`, `XAUTH_SRV_PREFIX`,
`XVFB_AUTH_LOG`, `XVFB_NOAUTH_DIR`), and build a chain the same way. To keep
one display on `-ac`, for example while debugging, create the root-owned marker
`${XVFB_NOAUTH_DIR}/noauth-N`.
