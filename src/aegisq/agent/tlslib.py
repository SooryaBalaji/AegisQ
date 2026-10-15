"""Ask the TLS library a server actually loads whether it accepts a group list, before any config changes.

Apache's ``configtest``, ``postfix check`` and ``doveconf -n`` do not load the group list, so a server
linked against OpenSSL older than 3.5 passes the test and then fails on reload (Apache exits). This check
loads that server's libssl in a separate Python process and calls ``SSL_CTX_set1_groups_list`` on it.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
from dataclasses import dataclass

from aegisq.proc import run_sync

# Files that link the server's TLS library, in the order distributions install them.
CANDIDATES: dict[str, tuple[str, ...]] = {
    "apache": (
        "/usr/lib/apache2/modules/mod_ssl.so",
        "/usr/lib64/httpd/modules/mod_ssl.so",
        "/usr/lib/httpd/modules/mod_ssl.so",
        "/usr/local/apache2/modules/mod_ssl.so",
        "/usr/libexec/apache2/mod_ssl.so",
    ),
    "postfix": (
        "/usr/lib/postfix/sbin/tlsmgr",
        "/usr/libexec/postfix/tlsmgr",
        "/usr/lib/postfix/tlsmgr",
    ),
    "dovecot": (
        "/usr/lib/dovecot/modules/libssl_iostream_openssl.so",
        "/usr/lib/dovecot/libssl_iostream_openssl.so",
        "/usr/lib64/dovecot/libssl_iostream_openssl.so",
        "/usr/local/lib/dovecot/libssl_iostream_openssl.so",
    ),
}

_CHECK = r"""
import ctypes, os, sys
crypto = os.path.join(os.path.dirname(sys.argv[1]), os.path.basename(sys.argv[1]).replace("libssl", "libcrypto"))
if os.path.exists(crypto):
    ctypes.CDLL(crypto, mode=ctypes.RTLD_GLOBAL)
lib = ctypes.CDLL(sys.argv[1])
ver = "unknown"
for fn in ("OpenSSL_version", "SSLeay_version"):
    f = getattr(lib, fn, None) or getattr(ctypes.CDLL(None), fn, None)
    if f:
        f.restype = ctypes.c_char_p
        f.argtypes = [ctypes.c_int]
        ver = (f(0) or b"").decode()
        break
meth = lib.TLS_server_method
meth.restype = ctypes.c_void_p
new = lib.SSL_CTX_new
new.restype = ctypes.c_void_p
new.argtypes = [ctypes.c_void_p]
ctx = new(meth())
groups = sys.argv[2].encode()
setter = getattr(lib, "SSL_CTX_set1_groups_list", None)
if setter:
    setter.restype = ctypes.c_int
    setter.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    ok = setter(ctx, groups)
else:
    ctrl = lib.SSL_CTX_ctrl
    ctrl.restype = ctypes.c_long
    ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_long, ctypes.c_void_p]
    ok = ctrl(ctx, 92, 0, ctypes.c_char_p(groups))
print("ok" if ok == 1 else "rejected", ver, sep="\t")
"""


@dataclass
class LibraryCheck:
    supported: bool | None  # None: could not tell
    library: str | None
    version: str | None
    detail: str


def locate(kind: str, explicit: str | None = None) -> str | None:
    """Path of the libssl the server loads, found with ldd, or None."""
    if explicit:
        return explicit if os.path.exists(explicit) else None
    for cand in CANDIDATES.get(kind, ()):
        path = cand if os.path.isabs(cand) else shutil.which(cand)
        if not path or not os.path.exists(path):
            continue
        if re.search(r"libssl\.so", os.path.basename(path)):
            return path
        ldd = shutil.which("ldd")
        if not ldd:
            return None
        res = run_sync([ldd, path], timeout=10)
        m = re.search(r"libssl\.so[^\s]*\s+=>\s+(\S+)", res.output)
        if m and os.path.exists(m.group(1)):
            return m.group(1)
    return None


def check(kind: str, groups: list[str], explicit: str | None = None) -> LibraryCheck:
    lib = locate(kind, explicit)
    if lib is None:
        return LibraryCheck(None, None, None, "could not find the server's TLS library on this host")
    if not all(re.fullmatch(r"[A-Za-z0-9_-]+", g) for g in groups):
        return LibraryCheck(None, lib, None, "group names not checkable")
    res = run_sync([sys.executable, "-I", "-c", _CHECK, lib, ":".join(groups)], timeout=15)
    line = res.stdout.strip().splitlines()[-1] if res.ok and res.stdout.strip() else ""
    verdict, _, version = line.partition("\t")
    if verdict not in ("ok", "rejected"):
        return LibraryCheck(None, lib, None, f"library check failed: {res.output.strip()[-200:]}")
    if verdict == "ok":
        return LibraryCheck(True, lib, version or None, f"{version or lib} accepts {':'.join(groups)}")
    return LibraryCheck(False, lib, version or None, f"{version or lib} rejects {':'.join(groups)}")
