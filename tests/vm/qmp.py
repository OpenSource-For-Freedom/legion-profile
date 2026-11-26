#!/usr/bin/env python3
"""Drives the test VM like a person at the keyboard, through QEMU's QMP and
serial sockets.

  qmp.py screenshot QMP_SOCKET FILE.png
  qmp.py type QMP_SOCKET TEXT        (letters, digits and - only, then Enter)
  qmp.py console-login SERIAL_SOCKET USER PASSWORD [banner|no-banner]
"""
import json
import socket
import sys
import time

KEYS = {"-": "minus", " ": "spc"}


def qmp(path):
    s = socket.socket(socket.AF_UNIX)
    s.connect(path)
    f = s.makefile("rw")
    f.readline()  # greeting

    def cmd(name, **args):
        f.write(json.dumps({"execute": name, "arguments": args}) + "\n")
        f.flush()
        while True:
            r = json.loads(f.readline())
            if "return" in r or "error" in r:
                if "error" in r:
                    raise SystemExit(f"QMP {name}: {r['error']}")
                return r["return"]

    cmd("qmp_capabilities")
    return cmd


def key(cmd, *names):
    cmd("send-key", keys=[{"type": "qcode", "data": n} for n in names])
    time.sleep(0.08)


def type_text(cmd, text):
    for ch in text:
        if ch.isupper():
            key(cmd, "shift", ch.lower())
        elif ch in KEYS:
            key(cmd, KEYS[ch])
        else:
            key(cmd, ch)
    key(cmd, "ret")


def console_login(path, user, password, want_banner=True):
    s = socket.socket(socket.AF_UNIX)
    s.connect(path)
    s.settimeout(1)
    seen = b""

    def until(token, limit=60):
        nonlocal seen
        end = time.time() + limit
        while time.time() < end:
            try:
                data = s.recv(4096)
            except socket.timeout:
                continue
            seen += data
            if token in seen:
                return True
        return False

    s.sendall(b"\r")
    if not until(b"login:"):
        raise SystemExit("no login prompt on the console")
    banner = b"Authorized use only" in seen
    seen = b""
    s.sendall(user.encode() + b"\r")
    if not until(b"Password:"):
        raise SystemExit("no password prompt")
    s.sendall(password.encode() + b"\r")
    seen = b""
    if not until(b"$ ", 30):
        raise SystemExit("no shell after login: " + seen.decode(errors="replace")[-300:])
    s.sendall(b"echo LOGGED-IN-AS-$(id -un); exit\r")
    ok = until(b"LOGGED-IN-AS-" + user.encode(), 15)
    # The banner may have been printed before this script connected. After
    # logout the console starts over and shows it again.
    if not banner:
        seen = b""
        banner = until(b"Authorized use only", 30 if want_banner else 10)
    print(f"console banner shown: {banner}; logged in: {ok}")
    raise SystemExit(0 if ok and banner == want_banner else 1)


if __name__ == "__main__":
    what = sys.argv[1]
    if what == "screenshot":
        qmp(sys.argv[2])("screendump", filename=sys.argv[3], format="png")
    elif what == "type":
        type_text(qmp(sys.argv[2]), sys.argv[3])
    elif what == "console-login":
        console_login(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5:6] != ["no-banner"])
