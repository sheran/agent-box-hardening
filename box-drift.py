#!/usr/bin/env python3
"""box-drift.py - record how a cloud VM changes underneath you.

Platform redeploys, image updates and agent sessions change files, processes
and packages without telling you. This logger takes snapshots and keeps a
history in SQLite so you can answer "what changed, and when?":

  * files under configured roots (+ single files): mode, owner, size, mtime
    and sha256 (cached by inode/size/mtime); `meta_only` paths skip hashing
  * processes matched to roles by regex (e.g. "browser", "x-server"):
    user, executable and a redacted command line
  * key/value state: output of version commands, package list digest
  * every difference becomes a row in `changes`; unless it matches a
    `no_event` pattern it also becomes a `notification` (and a line in
    notifications.jsonl) until someone marks it reported
  * hashes are labelled against the chain allowlist (chains/<set>/<ver>/*.sha256)
    so a change reads "now STOCK browser-launcher example-v1" instead of a hex string

Run it as the agent user (it never needs root); with "use_sudo": true it
uses `sudo -n sha256sum` for files it cannot read.

Usage:
  box-drift.py [--config FILE] [--label TEXT]          take a snapshot
  box-drift.py --add-event --kind K --path P --detail D  record an outside event
  box-drift.py --list-unreported | --mark-reported ID...|all
  box-drift.py --history PATH                           changes for one path
  box-drift.py --selftest                               temp files only
"""
import argparse
import fnmatch
import hashlib
import json
import os
import re
import sqlite3
import stat
import subprocess
import sys
import tempfile
from datetime import datetime

DEFAULT_CONFIG = os.path.expanduser("~/.config/box-drift/inventory.json")
SCHEMA = """
CREATE TABLE IF NOT EXISTS snapshots(id INTEGER PRIMARY KEY, ts TEXT, label TEXT);
CREATE TABLE IF NOT EXISTS file_versions(snapshot INTEGER, path TEXT, kind TEXT, mode TEXT,
  uid INTEGER, gid INTEGER, size INTEGER, mtime REAL, sha256 TEXT, target TEXT,
  PRIMARY KEY(snapshot, path));
CREATE TABLE IF NOT EXISTS proc_versions(snapshot INTEGER, role TEXT, uid INTEGER, exe TEXT,
  cmdline TEXT, count INTEGER, PRIMARY KEY(snapshot, role, uid, exe, cmdline));
CREATE TABLE IF NOT EXISTS kv_state(snapshot INTEGER, key TEXT, value TEXT, PRIMARY KEY(snapshot, key));
CREATE TABLE IF NOT EXISTS pkg_lists(digest TEXT PRIMARY KEY, ts TEXT, body TEXT);
CREATE TABLE IF NOT EXISTS changes(id INTEGER PRIMARY KEY, snapshot INTEGER, ts TEXT, kind TEXT,
  path TEXT, before TEXT, after TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY, change_id INTEGER, ts TEXT,
  summary TEXT, reported_at TEXT);
CREATE TABLE IF NOT EXISTS hash_cache(path TEXT PRIMARY KEY, dev INTEGER, ino INTEGER,
  size INTEGER, mtime_ns INTEGER, sha256 TEXT);
"""


def now():
    """Local time with its UTC offset, e.g. 2026-01-31T09:00:00+08:00."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def load_config(path):
    with open(path) as f:
        cfg = json.load(f)
    base = os.path.dirname(os.path.abspath(path))
    cfg.setdefault("db", os.path.expanduser("~/.local/state/box-drift/drift.sqlite"))
    cfg.setdefault("jsonl", os.path.join(os.path.dirname(cfg["db"]), "notifications.jsonl"))
    for key in ("roots", "single_files", "meta_only", "no_event", "exclude", "redact"):
        cfg.setdefault(key, [])
    cfg.setdefault("proc_roles", {})
    cfg.setdefault("version_cmds", {})
    cfg.setdefault("pkg_cmd", [])
    cfg.setdefault("use_sudo", False)
    cfg.setdefault("max_files", 20000)
    if cfg.get("chains_dir") and not os.path.isabs(cfg["chains_dir"]):
        cfg["chains_dir"] = os.path.join(base, cfg["chains_dir"])
    return cfg


def open_db(path):
    os.makedirs(os.path.dirname(path) or ".", mode=0o700, exist_ok=True)
    db = sqlite3.connect(path)
    db.executescript(SCHEMA)
    os.chmod(path, 0o600)
    return db


# ---- chain labels -------------------------------------------------------------
def chain_labels(chains_dir):
    """Map sha256 -> 'STOCK|SANDBOX-ONLY|HARDENED <set> <version>'."""
    labels = {}
    if not chains_dir or not os.path.isdir(chains_dir):
        return labels
    names = {"orig.sha256": "STOCK", "sandboxed.sha256": "SANDBOX-ONLY", "hardened.sha256": "HARDENED"}
    for root, _dirs, files in os.walk(chains_dir):
        for fn in files:
            if fn in names:
                with open(os.path.join(root, fn)) as f:
                    parts = f.read().split()
                h = parts[0] if parts else ""
                rel = os.path.relpath(root, chains_dir).split(os.sep)
                if re.fullmatch(r"[0-9a-f]{64}", h or "") and len(rel) == 2:
                    labels[h] = "%s %s %s" % (names[fn], rel[0], rel[1])
    return labels


# ---- collection ---------------------------------------------------------------
def matches(path, patterns):
    return any(fnmatch.fnmatch(path, p) for p in patterns)


def file_sha(db, path, st, use_sudo):
    row = db.execute("SELECT dev, ino, size, mtime_ns, sha256 FROM hash_cache WHERE path=?", (path,)).fetchone()
    key = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
    if row and tuple(row[:4]) == key:
        return row[4]
    h = None
    try:
        d = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                d.update(chunk)
        h = d.hexdigest()
    except PermissionError:
        if use_sudo:
            r = subprocess.run(["sudo", "-n", "sha256sum", "--", path], capture_output=True, text=True)
            if r.returncode == 0 and r.stdout:
                h = r.stdout.split()[0]
        if h is None:
            return "unreadable"
    except OSError:
        return "unreadable"
    db.execute("INSERT OR REPLACE INTO hash_cache VALUES(?,?,?,?,?,?)", (path,) + key + (h,))
    return h


def file_record(db, cfg, path):
    try:
        st = os.lstat(path)
    except OSError:
        return None
    rec = {"mode": oct(stat.S_IMODE(st.st_mode)), "uid": st.st_uid, "gid": st.st_gid,
           "size": st.st_size, "mtime": int(st.st_mtime), "sha256": "", "target": ""}
    if stat.S_ISLNK(st.st_mode):
        rec["kind"] = "symlink"
        rec["target"] = os.readlink(path)
    elif stat.S_ISDIR(st.st_mode):
        rec["kind"] = "dir"
        rec["size"] = rec["mtime"] = 0      # dir size/mtime churn is noise
    elif stat.S_ISREG(st.st_mode):
        rec["kind"] = "file"
        if not matches(path, cfg["meta_only"]):
            rec["sha256"] = file_sha(db, path, st, cfg["use_sudo"])
        else:
            rec["mtime"] = 0
    else:
        rec["kind"] = "other"
    return rec


def collect_files(db, cfg):
    out = {}
    paths = list(cfg["single_files"])
    for root in cfg["roots"]:
        for dirpath, dirs, files in os.walk(root, onerror=lambda e: None):
            dirs[:] = sorted(d for d in dirs if not matches(os.path.join(dirpath, d), cfg["exclude"]))
            paths.append(dirpath)
            paths.extend(os.path.join(dirpath, f) for f in sorted(files))
            if len(paths) > cfg["max_files"]:
                break
    for p in paths[: cfg["max_files"]]:
        if matches(p, cfg["exclude"]):
            continue
        rec = file_record(db, cfg, p)
        if rec:
            out[p] = rec
    return out


def redact(text, patterns):
    for pat in patterns:
        text = re.sub(pat, "[redacted]", text)
    return text


def collect_procs(cfg):
    roles = {r: re.compile(rx) for r, rx in cfg["proc_roles"].items()}
    out = {}
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open("/proc/%s/cmdline" % pid, "rb") as f:
                cmd = f.read().replace(b"\0", b" ").decode(errors="replace").strip()
            uid = os.stat("/proc/%s" % pid).st_uid
            try:
                exe = os.readlink("/proc/%s/exe" % pid)
            except OSError:
                exe = "?"
        except OSError:
            continue
        for role, rx in roles.items():
            if cmd and rx.search(cmd):
                # Drop per-process noise (numbers, temp names) so restarts do not count as changes.
                norm = re.sub(r"\b\d{3,}\b", "N", redact(cmd, cfg["redact"]))[:500]
                key = (role, uid, exe, norm)
                out[key] = out.get(key, 0) + 1
    return out


def collect_kv(db, cfg):
    kv = {}
    for name, argv in cfg["version_cmds"].items():
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=20)
            text = (r.stdout or r.stderr).strip()
            first = text.splitlines()[0][:300] if text else "rc=%d" % r.returncode
            kv["version:" + name] = redact(first, cfg["redact"])
        except (OSError, subprocess.SubprocessError):
            kv["version:" + name] = "unavailable"
    if cfg["pkg_cmd"]:
        try:
            body = subprocess.run(cfg["pkg_cmd"], capture_output=True, text=True, timeout=60).stdout
            digest = hashlib.sha256(body.encode()).hexdigest()
            db.execute("INSERT OR IGNORE INTO pkg_lists VALUES(?,?,?)", (digest, now(), body))
            kv["packages"] = digest
        except (OSError, subprocess.SubprocessError):
            kv["packages"] = "unavailable"
    return kv


# ---- snapshot and diff --------------------------------------------------------
def describe(rec, labels):
    if rec is None:
        return "absent"
    parts = [rec["kind"], rec["mode"], "%s:%s" % (rec["uid"], rec["gid"])]
    if rec["kind"] == "symlink":
        parts.append("-> " + rec["target"])
    if rec["sha256"]:
        parts.append(rec["sha256"][:12] + (" (" + labels[rec["sha256"]] + ")" if rec["sha256"] in labels else ""))
    return " ".join(parts)


def last_snapshot(db):
    row = db.execute("SELECT max(id) FROM snapshots").fetchone()
    return row[0]


def prev_files(db, snap):
    cols = "path, kind, mode, uid, gid, size, mtime, sha256, target"
    out = {}
    for r in db.execute("SELECT %s FROM file_versions WHERE snapshot=?" % cols, (snap,)):
        out[r[0]] = dict(zip(cols.split(", ")[1:], r[1:]))
    return out


def add_change(db, cfg, snap, kind, path, before, after, detail=""):
    ts = now()
    cur = db.execute("INSERT INTO changes(snapshot, ts, kind, path, before, after, detail) VALUES(?,?,?,?,?,?,?)",
                     (snap, ts, kind, path, before, after, detail))
    if matches(path, cfg["no_event"]):
        return
    summary = "%s %s: %s -> %s%s" % (kind, path, before, after, (" (" + detail + ")") if detail else "")
    n = db.execute("INSERT INTO notifications(change_id, ts, summary) VALUES(?,?,?)", (cur.lastrowid, ts, summary))
    os.makedirs(os.path.dirname(cfg["jsonl"]) or ".", mode=0o700, exist_ok=True)
    with open(cfg["jsonl"], "a") as f:
        f.write(json.dumps({"id": n.lastrowid, "ts": ts, "kind": kind, "path": path, "summary": summary}) + "\n")


def snapshot(db, cfg, label):
    labels = chain_labels(cfg.get("chains_dir"))
    prev = last_snapshot(db)
    snap = db.execute("INSERT INTO snapshots(ts, label) VALUES(?,?)", (now(), label or "")).lastrowid
    files = collect_files(db, cfg)
    for p, r in files.items():
        db.execute("INSERT INTO file_versions VALUES(?,?,?,?,?,?,?,?,?,?)",
                   (snap, p, r["kind"], r["mode"], r["uid"], r["gid"], r["size"], r["mtime"], r["sha256"], r["target"]))
    procs = collect_procs(cfg)
    for (role, uid, exe, cmd), count in procs.items():
        db.execute("INSERT INTO proc_versions VALUES(?,?,?,?,?,?)", (snap, role, uid, exe, cmd, count))
    kv = collect_kv(db, cfg)
    for k, v in kv.items():
        db.execute("INSERT INTO kv_state VALUES(?,?,?)", (snap, k, v))
    n = 0
    if prev is not None:
        old = prev_files(db, prev)
        for p in sorted(set(old) | set(files)):
            a, b = old.get(p), files.get(p)
            if a == b:
                continue
            if a and b and a["sha256"] == b["sha256"] and a["kind"] == b["kind"] and a["target"] == b["target"]:
                kind = "meta"
                if (a["mode"], a["uid"], a["gid"]) == (b["mode"], b["uid"], b["gid"]):
                    continue    # size/mtime only, content unchanged
            else:
                kind = "added" if a is None else "removed" if b is None else "modified"
            add_change(db, cfg, snap, kind, p, describe(a, labels), describe(b, labels))
            n += 1
        old_roles = {}
        for role, uid, exe, cmd in db.execute("SELECT role, uid, exe, cmdline FROM proc_versions WHERE snapshot=?", (prev,)):
            old_roles.setdefault(role, set()).add((uid, exe, cmd))
        new_roles = {}
        for role, uid, exe, cmd in procs:
            new_roles.setdefault(role, set()).add((uid, exe, cmd))
        for role in sorted(set(old_roles) | set(new_roles)):
            a, b = old_roles.get(role, set()), new_roles.get(role, set())
            if a != b:
                fmt = lambda s: "; ".join("uid %s %s" % (u, e) for u, e, _c in sorted(s)) or "none"
                add_change(db, cfg, snap, "process", "proc:" + role, fmt(a), fmt(b),
                           "%d new, %d gone command lines" % (len(b - a), len(a - b)))
                n += 1
        old_kv = dict(db.execute("SELECT key, value FROM kv_state WHERE snapshot=?", (prev,)).fetchall())
        for k in sorted(set(old_kv) | set(kv)):
            if old_kv.get(k) != kv.get(k):
                detail = ""
                if k == "packages":
                    detail = pkg_delta(db, old_kv.get(k), kv.get(k))
                add_change(db, cfg, snap, "state", k, str(old_kv.get(k)), str(kv.get(k)), detail)
                n += 1
    db.commit()
    return snap, n


def pkg_delta(db, d1, d2):
    def body(d):
        r = db.execute("SELECT body FROM pkg_lists WHERE digest=?", (d,)).fetchone()
        return set(r[0].splitlines()) if r else set()
    a, b = body(d1), body(d2)
    added, removed = sorted(b - a), sorted(a - b)
    return "+%d -%d: %s" % (len(added), len(removed), ", ".join(["+" + x for x in added[:10]] + ["-" + x for x in removed[:10]]))


# ---- events and notifications -------------------------------------------------
def add_event(db, cfg, kind, path, detail):
    snap = last_snapshot(db)
    add_change(db, cfg, snap, "event:" + kind, path, "", "", detail)
    db.commit()


def list_unreported(db):
    return db.execute("SELECT id, ts, summary FROM notifications WHERE reported_at IS NULL ORDER BY id").fetchall()


def mark_reported(db, ids):
    if ids == ["all"]:
        cur = db.execute("UPDATE notifications SET reported_at=? WHERE reported_at IS NULL", (now(),))
    else:
        cur = db.executemany("UPDATE notifications SET reported_at=? WHERE id=? AND reported_at IS NULL",
                             [(now(), int(i)) for i in ids])
    db.commit()
    return cur.rowcount


def history(db, path):
    return db.execute("SELECT ts, kind, before, after, detail FROM changes WHERE path=? ORDER BY id", (path,)).fetchall()


# ---- self-test ----------------------------------------------------------------
def selftest():
    results = []

    def check(cond, name):
        results.append(bool(cond))
        print("%s  %s" % ("PASS" if cond else "FAIL", name))

    with tempfile.TemporaryDirectory() as t:
        root = os.path.join(t, "root")
        os.makedirs(os.path.join(root, "bin"))
        os.makedirs(os.path.join(root, "cache"))
        stock, hardened = b"#!/bin/sh\necho stock\n", b"#!/bin/sh\necho hardened\n"
        chain = os.path.join(t, "chains", "launcher", "v1")
        os.makedirs(chain)
        for name, body in (("orig.sha256", stock), ("hardened.sha256", hardened)):
            with open(os.path.join(chain, name), "w") as f:
                f.write(hashlib.sha256(body).hexdigest() + "\n")
        launcher = os.path.join(root, "bin", "launcher")
        with open(launcher, "wb") as f:
            f.write(hardened)
        with open(os.path.join(root, "bin", "gone"), "w") as f:
            f.write("x")
        with open(os.path.join(root, "cache", "noise"), "w") as f:
            f.write("1")
        ver = os.path.join(t, "version")
        with open(ver, "w") as f:
            f.write("tool 1.0 token=abc123\n")
        pkgs = os.path.join(t, "pkgs")
        with open(pkgs, "w") as f:
            f.write("alpha 1\nbeta 1\n")
        cfgfile = os.path.join(t, "inventory.json")
        with open(cfgfile, "w") as f:
            json.dump({"db": os.path.join(t, "state", "drift.sqlite"), "roots": [root],
                       "no_event": [os.path.join(root, "cache") + "/*"], "chains_dir": "chains",
                       "redact": [r"token=\S+"], "version_cmds": {"tool": ["cat", ver]},
                       "pkg_cmd": ["cat", pkgs], "proc_roles": {"sleeper": r"^sleep 4242$"}}, f)
        cfg = load_config(cfgfile)
        db = open_db(cfg["db"])
        check(oct(stat.S_IMODE(os.stat(cfg["db"]).st_mode)) == "0o600", "database created 600")
        s1, n1 = snapshot(db, cfg, "first")
        check(n1 == 0, "first snapshot records no changes")
        # Platform "redeploy": launcher reverted to stock, a file removed, one added, a mode change.
        with open(launcher, "wb") as f:
            f.write(stock)
        os.remove(os.path.join(root, "bin", "gone"))
        with open(os.path.join(root, "bin", "new"), "w") as f:
            f.write("y")
        os.chmod(os.path.join(root, "cache"), 0o777)
        with open(os.path.join(root, "cache", "noise"), "w") as f:
            f.write("2")
        with open(ver, "w") as f:
            f.write("tool 2.0 token=def456\n")
        with open(pkgs, "w") as f:
            f.write("alpha 1\nbeta 2\ngamma 1\n")
        sleeper = subprocess.Popen(["sleep", "4242"])
        try:
            s2, n2 = snapshot(db, cfg, "second")
        finally:
            sleeper.kill()
            sleeper.wait()
        rows = {(k, p): (b, a, d) for _ts, k, p, b, a, d in
                db.execute("SELECT ts, kind, path, before, after, detail FROM changes WHERE snapshot=?", (s2,))}
        lc = rows.get(("modified", launcher))
        check(lc and "HARDENED launcher v1" in lc[0] and "STOCK launcher v1" in lc[1], "launcher revert labelled HARDENED -> STOCK")
        check(("removed", os.path.join(root, "bin", "gone")) in rows, "removed file recorded")
        check(("added", os.path.join(root, "bin", "new")) in rows, "added file recorded")
        check(("meta", os.path.join(root, "cache")) in rows, "mode-only change recorded as meta")
        v = rows.get(("state", "version:tool"))
        check(v and "2.0" in v[1] and "def456" not in v[1] and "[redacted]" in v[1], "version change recorded, secret redacted")
        p = rows.get(("state", "packages"))
        check(p and "+gamma 1" in p[2] and "+beta 2" in p[2] and "-beta 1" in p[2], "package delta listed")
        check(("process", "proc:sleeper") in rows, "process role appearance recorded")
        un = list_unreported(db)
        summaries = " ".join(s for _i, _t, s in un)
        check(os.path.join(root, "cache", "noise") in " ".join(p for _k, p in rows) and
              os.path.join(root, "cache", "noise") not in summaries, "no_event path recorded but not notified")
        check(launcher in summaries, "launcher change notified")
        add_event(db, cfg, "fastfix-fixed", launcher, "re-hardened")
        check(any("event:fastfix-fixed" in s for _i, _t, s in list_unreported(db)), "outside event recorded")
        with open(cfg["jsonl"]) as f:
            lines = [json.loads(x) for x in f]
        check(len(lines) == len(list_unreported(db)), "notifications.jsonl mirrors notifications")
        first = list_unreported(db)[0][0]
        check(mark_reported(db, [str(first)]) == 1 and mark_reported(db, [str(first)]) == 0, "mark one reported (idempotent)")
        mark_reported(db, ["all"])
        check(list_unreported(db) == [], "mark all reported")
        s3, n3 = snapshot(db, cfg, "third")
        check(n3 == 1, "unchanged box: only the vanished process differs (%d change)" % n3)
        ts = db.execute("SELECT ts FROM snapshots WHERE id=?", (s3,)).fetchone()[0]
        check(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d\d:\d\d", ts), "timestamps are local with offset")
        check(len(history(db, launcher)) == 2, "history for one path")
        db.close()
    ok = all(results)
    print("drift selftest: %d passed, %d failed" % (results.count(True), results.count(False)))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="Record file/process/package drift on a VM.")
    ap.add_argument("--config", default=os.environ.get("BOX_DRIFT_CONFIG", DEFAULT_CONFIG))
    ap.add_argument("--label", default="")
    ap.add_argument("--add-event", action="store_true")
    ap.add_argument("--kind", default="note")
    ap.add_argument("--path", default="")
    ap.add_argument("--detail", default="")
    ap.add_argument("--list-unreported", action="store_true")
    ap.add_argument("--mark-reported", nargs="+", metavar="ID")
    ap.add_argument("--history", metavar="PATH")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    os.umask(0o077)
    cfg = load_config(a.config)
    db = open_db(cfg["db"])
    if a.add_event:
        add_event(db, cfg, re.sub(r"[^A-Za-z0-9_.-]", "_", a.kind), a.path, a.detail[:1000])
    elif a.list_unreported:
        for i, ts, s in list_unreported(db):
            print("%d\t%s\t%s" % (i, ts, s))
    elif a.mark_reported:
        print("marked %d" % mark_reported(db, a.mark_reported))
    elif a.history:
        for row in history(db, a.history):
            print("\t".join(str(x) for x in row))
    else:
        snap, n = snapshot(db, cfg, a.label)
        print("snapshot %d: %d change(s), %d unreported" % (snap, n, len(list_unreported(db))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
