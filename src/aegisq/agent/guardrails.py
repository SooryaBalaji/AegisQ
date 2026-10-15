"""Patch guardrails. These live in code, not in the prompt: whatever the model writes, only the
key-exchange lines can change, and only to values policy allows: ``ssl_ecdh_curve`` and
``ssl_protocols`` (nginx), ``KexAlgorithms`` (sshd), ``SSLOpenSSLConfCmd Groups`` (Apache),
``ssl-default-bind-curves`` (HAProxy), ``curves`` (Caddy), ``tls_eecdh_auto_curves`` (Postfix)
and ``ssl_curve_list`` (Dovecot).

A proposed patch is a unified diff. It is parsed strictly (no fuzz, exact
context, hunk counts checked), every added or removed line must be exactly one
allowed directive, values are checked against an allowlist, and the result is
re-diffed against the original as a second, independent check.
"""

from __future__ import annotations

import difflib
import hashlib
import re
from dataclasses import dataclass, field

from aegisq.crypto_registry import SSH_WEAK_KEX, group_by_name, ssh_kex_is_pq

ALLOWED_DIRECTIVES = ("ssl_ecdh_curve", "ssl_protocols")
MAX_DIFF_BYTES = 64 * 1024
MAX_CONFIG_BYTES = 1024 * 1024

# One directive, alone on its line, optional trailing comment. The value may not contain
# ; { } quotes, backslashes, $ or # so a line can never smuggle a second directive or a variable.
DIRECTIVE_RE = re.compile(
    r"^(?P<indent>[ \t]*)(?P<name>ssl_ecdh_curve|ssl_protocols)[ \t]+(?P<value>[^;{}'\"\\$#\r\n]+?)[ \t]*;"
    r"(?P<comment>[ \t]*#[^\r\n]*)?[ \t]*$"
)
# sshd_config: keyword (any case), whitespace or '=', then an algorithm list. No trailing comment, no quotes.
SSHD_DIRECTIVE_RE = re.compile(
    r"^(?P<indent>[ \t]*)(?P<name>KexAlgorithms)(?:[ \t]+|[ \t]*=[ \t]*)(?P<value>[A-Za-z0-9@._,+^-]+)[ \t]*$",
    re.IGNORECASE,
)
SSHD_MATCH_RE = re.compile(r"^[ \t]*Match[ \t]", re.IGNORECASE)
SSHD_KEX_PREFIX_RE = re.compile(r"^[ \t]*KexAlgorithms\b", re.IGNORECASE)
HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
TLS_PROTOCOLS = ("TLSv1.2", "TLSv1.3")
FORBIDDEN_PROTOCOLS = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")


class PatchRejected(ValueError):
    """The patch violates a guardrail. The message is safe to show the model."""


@dataclass
class Policy:
    allowed_groups: list[str]
    require_classical_fallback: bool = True
    min_tls_version: str = "TLSv1.2"
    allowed_ssh_kex: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Dialect:
    name: str
    directives: tuple[str, ...]
    line_re: re.Pattern[str]
    label: str
    groups: tuple[str, ...] = ()  # directives whose value is a TLS group list
    sep: str = ":"  # regex that splits a group list
    structure: str = "braces"  # braces | sshd | haproxy | postfix | none
    prefix_re: re.Pattern[str] | None = None  # any line that starts the directive, even one we cannot parse


NGINX = Dialect(
    "nginx",
    ALLOWED_DIRECTIVES,
    DIRECTIVE_RE,
    "ssl_ecdh_curve/ssl_protocols",
    groups=("ssl_ecdh_curve",),
    prefix_re=re.compile(r"^[ \t]*ssl_ecdh_curve\b"),
)
SSHD = Dialect("sshd", ("KexAlgorithms",), SSHD_DIRECTIVE_RE, "KexAlgorithms", structure="sshd")
APACHE = Dialect(
    "apache",
    ("SSLOpenSSLConfCmd Groups", "SSLOpenSSLConfCmd Curves"),
    re.compile(
        r"^(?P<indent>[ \t]*)(?P<name>SSLOpenSSLConfCmd[ \t]+(?:Groups|Curves))[ \t]+(?P<value>[A-Za-z0-9_:-]+)[ \t]*$",
        re.IGNORECASE,
    ),
    "SSLOpenSSLConfCmd Groups",
    groups=("SSLOpenSSLConfCmd Groups", "SSLOpenSSLConfCmd Curves"),
    structure="none",
    prefix_re=re.compile(r"^[ \t]*SSLOpenSSLConfCmd[ \t]+[\"']?(?:Groups|Curves)\b", re.IGNORECASE),
)
HAPROXY = Dialect(
    "haproxy",
    ("ssl-default-bind-curves",),
    re.compile(r"^(?P<indent>[ \t]*)(?P<name>ssl-default-bind-curves)[ \t]+(?P<value>[A-Za-z0-9_:-]+)[ \t]*$"),
    "ssl-default-bind-curves",
    groups=("ssl-default-bind-curves",),
    structure="haproxy",
    prefix_re=re.compile(r"^[ \t]*ssl-default-bind-curves\b"),
)
CADDY = Dialect(
    "caddy",
    ("curves",),
    re.compile(r"^(?P<indent>[ \t]*)(?P<name>curves)[ \t]+(?P<value>[a-z0-9_]+(?:[ \t]+[a-z0-9_]+)*)[ \t]*$"),
    "curves",
    groups=("curves",),
    sep=r"[ \t]+",
    prefix_re=re.compile(r"^[ \t]*curves\b"),
)
POSTFIX = Dialect(
    "postfix",
    ("tls_eecdh_auto_curves",),
    re.compile(
        r"^(?P<indent>)(?P<name>tls_eecdh_auto_curves)[ \t]*=[ \t]*"
        r"(?P<value>[A-Za-z0-9_-]+(?:[ \t]*,[ \t]*[A-Za-z0-9_-]+|[ \t]+[A-Za-z0-9_-]+)*)[ \t]*$"
    ),
    "tls_eecdh_auto_curves",
    groups=("tls_eecdh_auto_curves",),
    sep=r"[ \t]*,[ \t]*|[ \t]+",
    structure="postfix",
    prefix_re=re.compile(r"^[ \t]*tls_eecdh_auto_curves\b"),
)
DOVECOT = Dialect(
    "dovecot",
    ("ssl_curve_list",),
    re.compile(r"^(?P<indent>[ \t]*)(?P<name>ssl_curve_list)[ \t]*=[ \t]*(?P<value>[A-Za-z0-9_:-]+)[ \t]*$"),
    "ssl_curve_list",
    groups=("ssl_curve_list",),
    prefix_re=re.compile(r"^[ \t]*ssl_curve_list\b"),
)
DIALECTS = {d.name: d for d in (NGINX, SSHD, APACHE, HAPROXY, CADDY, POSTFIX, DOVECOT)}
HAPROXY_SECTIONS = re.compile(
    r"^[ \t]*(global|defaults|frontend|backend|listen|peers|resolvers|userlist|program|http-errors|ring|mailers|"
    r"cache|log-forward|crt-store|traces|acme)(?:[ \t]|$)"
)


@dataclass
class Hunk:
    old_start: int
    old_len: int
    new_start: int
    new_len: int
    lines: list[str] = field(default_factory=list)  # each starts with ' ', '-' or '+'


@dataclass
class ValidatedPatch:
    diff: str
    new_text: str
    diff_sha256: str
    changes: list[str]  # human-readable "- old / + new" pairs


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# --------------------------------------------------------------- parsing ---


def parse_unified_diff(diff: str) -> list[Hunk]:
    if len(diff.encode("utf-8")) > MAX_DIFF_BYTES:
        raise PatchRejected("diff too large")
    if "\x00" in diff:
        raise PatchRejected("diff contains NUL bytes")
    lines = diff.replace("\r\n", "\n").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    hunks: list[Hunk] = []
    i = 0
    headers = {"---": 0, "+++": 0}
    while i < len(lines):
        line = lines[i]
        if not hunks and line.startswith(("--- ", "+++ ", "diff ", "index ")):
            # File headers are only legal before the first hunk; one file per patch.
            if line[:3] in headers:
                headers[line[:3]] += 1
                if headers[line[:3]] > 1:
                    raise PatchRejected("diff touches more than one file")
            i += 1
            continue
        m = HUNK_RE.match(line)
        if not m:
            raise PatchRejected(f"unexpected diff line {i + 1}: {line[:80]!r}")
        h = Hunk(
            int(m.group(1)),
            int(m.group(2)) if m.group(2) is not None else 1,
            int(m.group(3)),
            int(m.group(4)) if m.group(4) is not None else 1,
        )
        i += 1
        old_seen = new_seen = 0
        while i < len(lines) and (old_seen < h.old_len or new_seen < h.new_len):
            body = lines[i]
            if body.startswith("\\"):
                i += 1
                continue
            tag = body[:1]
            if tag == " " or body == "":
                h.lines.append(" " + body[1:])
                old_seen += 1
                new_seen += 1
            elif tag == "-":
                h.lines.append(body)
                old_seen += 1
            elif tag == "+":
                h.lines.append(body)
                new_seen += 1
            else:
                raise PatchRejected(f"bad hunk line {i + 1}: {body[:80]!r}")
            i += 1
        while i < len(lines) and lines[i].startswith("\\"):
            i += 1
        if old_seen != h.old_len or new_seen != h.new_len:
            raise PatchRejected(
                f"hunk @@ -{h.old_start},{h.old_len} +{h.new_start},{h.new_len} @@ has "
                f"{old_seen} old / {new_seen} new lines; counts do not match"
            )
        hunks.append(h)
    if not hunks:
        raise PatchRejected("diff contains no hunks")
    return hunks


def apply_hunks(original: str, hunks: list[Hunk]) -> str:
    """Apply hunks with exact context matching and no offset fuzz."""
    src = original.split("\n")
    out: list[str] = []
    pos = 0  # index into src
    for h in hunks:
        start = h.old_start - 1 if h.old_len > 0 else h.old_start
        if start < pos:
            raise PatchRejected("hunks overlap or are out of order")
        if start > len(src):
            raise PatchRejected(f"hunk starts beyond end of file (line {h.old_start})")
        out.extend(src[pos:start])
        pos = start
        for line in h.lines:
            tag, text = line[:1], line[1:]
            if tag in (" ", "-"):
                if pos >= len(src) or src[pos] != text:
                    found = src[pos] if pos < len(src) else "<EOF>"
                    raise PatchRejected(f"context mismatch at line {pos + 1}: expected {text!r}, found {found!r}")
                if tag == " ":
                    out.append(text)
                pos += 1
            else:
                out.append(text)
    out.extend(src[pos:])
    return "\n".join(out)


# ------------------------------------------------------------ validation ---


def _check_value(name: str, value: str, policy: Policy, dialect: Dialect = NGINX) -> None:
    if name in dialect.groups:
        _check_groups(name, re.split(dialect.sep, value.strip()), policy)
    elif name == "KexAlgorithms":
        _check_ssh_kex(value, policy)
    elif name == "ssl_protocols":
        _check_protocols(value, policy)
    else:  # pragma: no cover - regex only matches allowed names
        raise PatchRejected(f"directive {name} not allowed")


def _check_groups(name: str, parts: list[str], policy: Policy) -> None:
    if any(not p for p in parts):
        raise PatchRejected(f"{name} has an empty group")
    allowed = {g.lower() for g in policy.allowed_groups}
    seen: set[str] = set()
    pq = classical = 0
    for p in parts:
        key = p.lower()
        if key not in allowed:
            raise PatchRejected(f"group {p!r} is not in the allowed list")
        if key in seen:
            raise PatchRejected(f"group {p!r} listed twice")
        seen.add(key)
        info = group_by_name(p)
        if info is None or info.obsolete:
            raise PatchRejected(f"group {p!r} is unknown or obsolete")
        if info.pq:
            pq += 1
        else:
            classical += 1
    if pq == 0:
        raise PatchRejected(f"{name} must include a post-quantum hybrid group such as X25519MLKEM768")
    first = group_by_name(parts[0])
    if first is None or not first.pq:
        raise PatchRejected("the post-quantum hybrid group must come first so it is preferred")
    if policy.require_classical_fallback and classical == 0:
        raise PatchRejected("policy requires a classical fallback (e.g. X25519) so older clients still connect")


def _check_protocols(value: str, policy: Policy) -> None:
    toks = value.split()
    if not toks:
        raise PatchRejected("ssl_protocols is empty")
    for t in toks:
        if t in FORBIDDEN_PROTOCOLS:
            raise PatchRejected(f"{t} is deprecated and may not be enabled")
        if t not in TLS_PROTOCOLS:
            raise PatchRejected(f"unknown protocol {t!r}")
    if len(set(toks)) != len(toks):
        raise PatchRejected("ssl_protocols lists a protocol twice")
    if "TLSv1.3" not in toks:
        raise PatchRejected("TLSv1.3 is required: hybrid ML-KEM key exchange only exists in TLS 1.3")
    if policy.min_tls_version == "TLSv1.3" and "TLSv1.2" in toks:
        raise PatchRejected("policy forbids TLSv1.2")


def _check_ssh_kex(value: str, policy: Policy) -> None:
    if value[:1] in ("+", "-", "^"):
        raise PatchRejected("KexAlgorithms must be an explicit list (no +, - or ^ modifiers)")
    parts = value.split(",")
    if any(not p for p in parts):
        raise PatchRejected("KexAlgorithms has an empty entry")
    allowed = set(policy.allowed_ssh_kex)
    seen: set[str] = set()
    pq = classical = 0
    for p in parts:
        if p in SSH_WEAK_KEX:
            raise PatchRejected(f"{p!r} is a weak key exchange and may not be enabled")
        if p not in allowed:
            raise PatchRejected(f"key exchange {p!r} is not in the allowed list")
        if p in seen:
            raise PatchRejected(f"key exchange {p!r} listed twice")
        seen.add(p)
        if ssh_kex_is_pq(p):
            pq += 1
        else:
            classical += 1
    if pq == 0:
        raise PatchRejected("KexAlgorithms must include a post-quantum hybrid such as mlkem768x25519-sha256")
    if not ssh_kex_is_pq(parts[0]):
        raise PatchRejected("the post-quantum hybrid must come first so it is preferred")
    if policy.require_classical_fallback and classical == 0:
        raise PatchRejected(
            "policy requires a classical fallback (e.g. curve25519-sha256) so older clients still connect"
        )


def _check_line(line: str, policy: Policy, dialect: Dialect = NGINX) -> str:
    m = dialect.line_re.match(line)
    if not m:
        raise PatchRejected(f"change outside {dialect.label} refused: {line.strip()[:100]!r}")
    return _canon(m.group("name"), dialect)


def _canon(name: str, dialect: Dialect) -> str:
    flat = " ".join(name.split()).lower()
    return next(d for d in dialect.directives if d.lower() == flat)


def validate_patch(original: str, diff: str, policy: Policy, dialect: Dialect = NGINX) -> ValidatedPatch:
    if len(original.encode("utf-8")) > MAX_CONFIG_BYTES:
        raise PatchRejected("config too large")
    hunks = parse_unified_diff(diff)
    removed: dict[str, int] = dict.fromkeys(dialect.directives, 0)
    added: dict[str, int] = dict.fromkeys(dialect.directives, 0)
    changes: list[str] = []
    for h in hunks:
        for line in h.lines:
            tag, text = line[:1], line[1:]
            if tag == "-":
                removed[_check_line(text, policy, dialect)] += 1
                changes.append(f"- {text.strip()}")
            elif tag == "+":
                name = _check_line(text, policy, dialect)
                m = dialect.line_re.match(text)
                assert m is not None
                _check_value(name, m.group("value"), policy, dialect)
                added[name] += 1
                changes.append(f"+ {text.strip()}")
    for d in dialect.directives:
        if removed[d] > added[d]:
            raise PatchRejected(f"patch deletes {d} without replacing it")
    if not any(added.values()):
        raise PatchRejected("patch changes nothing")

    new_text = apply_hunks(original, hunks)
    if new_text == original:
        raise PatchRejected("patch is a no-op")
    _independent_check(original, new_text, policy, dialect)
    if dialect.structure == "sshd":
        _check_sshd_structure(new_text)
    elif dialect.structure == "haproxy":
        _check_haproxy_structure(new_text)
    elif dialect.structure == "postfix":
        _check_postfix_structure(new_text)
    elif dialect.structure == "braces":
        _check_braces(new_text)
    return ValidatedPatch(diff=diff, new_text=new_text, diff_sha256=sha256_text(diff), changes=changes)


def _independent_check(original: str, new_text: str, policy: Policy, dialect: Dialect = NGINX) -> None:
    """Re-diff the result with difflib: every changed line must be an allowed directive."""
    a, b = original.split("\n"), new_text.split("\n")
    sm = difflib.SequenceMatcher(a=a, b=b, autojunk=False)
    for op, i1, i2, j1, j2 in sm.get_opcodes():
        if op == "equal":
            continue
        for line in a[i1:i2]:
            _check_line(line, policy, dialect)
        for line in b[j1:j2]:
            name = _check_line(line, policy, dialect)
            m = dialect.line_re.match(line)
            assert m is not None
            _check_value(name, m.group("value"), policy, dialect)


def _check_sshd_structure(text: str) -> None:
    """KexAlgorithms is global-only: a line after the first Match block would be ignored or rejected."""
    in_match = False
    for line in text.split("\n"):
        if SSHD_MATCH_RE.match(line):
            in_match = True
        elif in_match and SSHD_KEX_PREFIX_RE.match(line):
            raise PatchRejected("KexAlgorithms inside a Match block is not allowed")


def _check_haproxy_structure(text: str) -> None:
    """ssl-default-bind-curves is a global keyword: anywhere else HAProxy refuses to start."""
    section = None
    for line in text.split("\n"):
        m = HAPROXY_SECTIONS.match(line)
        if m:
            section = m.group(1)
        elif HAPROXY.prefix_re and HAPROXY.prefix_re.match(line) and section != "global":
            raise PatchRejected("ssl-default-bind-curves is only allowed in the global section")


def _check_postfix_structure(text: str) -> None:
    """In main.cf a line that starts with whitespace continues the previous one, so a rewritten
    tls_eecdh_auto_curves line must not be followed by a continuation."""
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if POSTFIX.prefix_re and POSTFIX.prefix_re.match(line):
            if line[:1] in (" ", "\t"):
                raise PatchRejected("tls_eecdh_auto_curves may not be indented (that makes it a continuation line)")
            nxt = lines[i + 1] if i + 1 < len(lines) else ""
            if nxt.strip() and nxt[:1] in (" ", "\t"):
                raise PatchRejected("tls_eecdh_auto_curves continues onto the next line; edit it by hand")


def _check_braces(text: str) -> None:
    depth = 0
    for ch in _strip_comments(text):
        depth += (ch == "{") - (ch == "}")
        if depth < 0:
            raise PatchRejected("unbalanced braces after patch")
    if depth != 0:
        raise PatchRejected("unbalanced braces after patch")


def _strip_comments(text: str) -> str:
    return "\n".join(line.split("#", 1)[0] for line in text.split("\n"))


# ------------------------------------------------------------ generation ---


def make_patch(
    original: str,
    filename: str,
    ssl_ecdh_curve: str | None = None,
    ssl_protocols: str | None = None,
) -> str:
    """Build a minimal unified diff that sets the given directive values.

    Existing directive lines are rewritten in place (indentation and trailing
    comments kept). If ``ssl_ecdh_curve`` is absent, it is inserted after each
    ``ssl_certificate_key`` line, which marks every TLS server block.
    """
    if ssl_ecdh_curve is None and ssl_protocols is None:
        raise PatchRejected("nothing to change: give ssl_ecdh_curve and/or ssl_protocols")
    wanted = {k: v for k, v in (("ssl_ecdh_curve", ssl_ecdh_curve), ("ssl_protocols", ssl_protocols)) if v}
    for v in wanted.values():
        if re.search(r"[;{}'\"\\$#\r\n]", v):
            raise PatchRejected("directive values may not contain ; { } quotes \\ $ # or newlines")
    lines = original.split("\n")
    found = dict.fromkeys(wanted, False)
    out: list[str] = []
    for line in lines:
        m = DIRECTIVE_RE.match(line)
        if m and m.group("name") in wanted:
            found[m.group("name")] = True
            out.append(f"{m.group('indent')}{m.group('name')} {wanted[m.group('name')]};{m.group('comment') or ''}")
        else:
            other = re.match(r"^\s*(ssl_ecdh_curve|ssl_protocols)\b", line)
            if other and other.group(1) in wanted:
                raise PatchRejected(f"cannot safely rewrite line: {line.strip()[:80]!r}")
            out.append(line)
    missing = [k for k, v in found.items() if not v]
    if missing:
        inserted = []
        for line in out:
            inserted.append(line)
            m = re.match(r"^([ \t]*)ssl_certificate_key\s", line)
            if m:
                inserted.extend(f"{m.group(1)}{name} {wanted[name]};" for name in missing)
        if inserted == out:
            raise PatchRejected("no ssl_certificate_key line found: this does not look like a TLS server config")
        out = inserted
    new_text = "\n".join(out)
    if new_text == original:
        raise PatchRejected("config already has these values")
    return _unified(original, new_text, filename)


def make_sshd_patch(original: str, filename: str, kex_algorithms: str) -> str:
    """Set the global KexAlgorithms. Existing global lines are rewritten in place; otherwise the line is
    inserted before the first directive, because sshd uses the first value it reads."""
    if not re.fullmatch(r"[A-Za-z0-9@._,-]+", kex_algorithms or ""):
        raise PatchRejected("KexAlgorithms must be a comma-separated list of algorithm names")
    out: list[str] = []
    found = in_match = False
    for line in original.split("\n"):
        if SSHD_MATCH_RE.match(line):
            in_match = True
        m = SSHD_DIRECTIVE_RE.match(line)
        if m and not in_match:
            found = True
            out.append(f"{m.group('indent')}KexAlgorithms {kex_algorithms}")
            continue
        if SSHD_KEX_PREFIX_RE.match(line) and not in_match:
            raise PatchRejected(f"cannot safely rewrite line: {line.strip()[:80]!r}")
        out.append(line)
    if not found:
        idx = next((i for i, x in enumerate(out) if x.strip() and not x.lstrip().startswith("#")), len(out))
        if idx == len(out) and out and out[-1] == "":
            idx -= 1
        out.insert(idx, f"KexAlgorithms {kex_algorithms}")
    new_text = "\n".join(out)
    if new_text == original:
        raise PatchRejected("config already has these values")
    return _unified(original, new_text, filename)


def _unified(original: str, new_text: str, filename: str) -> str:
    # Split on "\n" exactly as apply_hunks does, so line numbers agree even without a final newline.
    diff_lines = difflib.unified_diff(
        original.split("\n"), new_text.split("\n"), fromfile=f"a/{filename}", tofile=f"b/{filename}", n=3, lineterm=""
    )
    return "\n".join(diff_lines) + "\n"


def current_directives(text: str, dialect: Dialect = NGINX) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {d: [] for d in dialect.directives}
    in_match = False
    for line in text.split("\n"):
        if dialect is SSHD and SSHD_MATCH_RE.match(line):
            in_match = True
        m = dialect.line_re.match(line)
        if m and not in_match:
            out[_canon(m.group("name"), dialect)].append(m.group("value").strip())
    return out


def current_groups(text: str, dialect: Dialect) -> list[str]:
    """Every group named on the dialect's group lines, in order, without duplicates."""
    seen: list[str] = []
    for name, values in current_directives(text, dialect).items():
        if name not in dialect.groups:
            continue
        for v in values:
            for g in re.split(dialect.sep, v.strip()):
                if g and g.lower() not in {x.lower() for x in seen}:
                    seen.append(g)
    return seen


# Names each server accepts. Caddy (Go crypto/tls) has its own lower-case list.
CADDY_NAMES = {
    "x25519mlkem768": "x25519mlkem768",
    "x25519": "x25519",
    "secp256r1": "secp256r1",
    "prime256v1": "secp256r1",
    "p-256": "secp256r1",
    "secp384r1": "secp384r1",
    "p-384": "secp384r1",
    "secp521r1": "secp521r1",
    "p-521": "secp521r1",
}


def render_groups(kind: str, groups: list[str]) -> str:
    if kind == "caddy":
        out: list[str] = []
        for g in groups:
            name = CADDY_NAMES.get(g.lower())
            if name is None:
                raise PatchRejected(f"Caddy does not support the group {g!r}")
            if name not in out:
                out.append(name)
        return " ".join(out)
    if kind == "postfix":
        return ", ".join(groups)
    return ":".join(groups)


def make_groups_patch(original: str, filename: str, kind: str, groups: list[str]) -> str:
    """Set the TLS group list for Apache, HAProxy, Caddy, Postfix or Dovecot.

    Existing lines are rewritten in place, keeping indentation. When there is none, a line is
    added where the server reads it: after each SSLCertificateKeyFile (Apache), at the top of the
    global section (HAProxy) or at the end of the file (Postfix, Dovecot). Caddy is never given a
    new line, because Caddy 2.10 and later already prefer X25519MLKEM768 when no curves are set.
    """
    d = DIALECTS.get(kind)
    if d is None or not d.groups or kind == "nginx":
        raise PatchRejected(f"no group-list patcher for {kind!r}")
    if not groups:
        raise PatchRejected("no groups given")
    for g in groups:
        if not re.fullmatch(r"[A-Za-z0-9_-]+", g):
            raise PatchRejected(f"bad group name {g!r}")
    value = render_groups(kind, groups)
    lines = original.split("\n")
    out: list[str] = []
    found = False
    section = None
    for line in lines:
        if kind == "haproxy":
            sm = HAPROXY_SECTIONS.match(line)
            if sm:
                section = sm.group(1)
            if re.match(r"^[ \t]*bind[ \t].*[ \t]curves[ \t]", line):
                raise PatchRejected("a bind line sets its own curves, which override the global list; edit it by hand")
        m = d.line_re.match(line)
        if m and (kind != "haproxy" or section == "global"):
            found = True
            out.append(_render_line(kind, m.group("indent"), m.group("name"), value))
            continue
        if d.prefix_re and d.prefix_re.match(line):
            raise PatchRejected(f"cannot safely rewrite line: {line.strip()[:80]!r}")
        out.append(line)
    if not found:
        out = _insert_groups(kind, out, value)
    new_text = "\n".join(out)
    if new_text == original:
        raise PatchRejected("config already has these values")
    return _unified(original, new_text, filename)


def _render_line(kind: str, indent: str, name: str, value: str) -> str:
    if kind in ("postfix", "dovecot"):
        return f"{indent}{name} = {value}"
    return f"{indent}{name} {value}"


def _insert_groups(kind: str, lines: list[str], value: str) -> list[str]:
    if kind == "caddy":
        raise PatchRejected(
            "Caddy 2.10 and later prefer X25519MLKEM768 when no curves are set, so there is nothing to add: "
            "upgrade Caddy instead"
        )
    if kind == "apache":
        for anchor in ("SSLCertificateKeyFile", "SSLCertificateFile"):
            out: list[str] = []
            for line in lines:
                out.append(line)
                m = re.match(rf"^([ \t]*){anchor}[ \t]", line, re.IGNORECASE)
                if m:
                    out.append(f"{m.group(1)}SSLOpenSSLConfCmd Groups {value}")
            if len(out) > len(lines):
                return out
        raise PatchRejected("no SSLCertificateFile line found: this does not look like a TLS virtual host")
    if kind == "haproxy":
        for i, line in enumerate(lines):
            if re.match(r"^[ \t]*global[ \t]*(#.*)?$", line):
                nxt = next((x for x in lines[i + 1 :] if x.strip()), "")
                indent = re.match(r"^[ \t]*", nxt).group(0) if nxt and not HAPROXY_SECTIONS.match(nxt) else "    "  # type: ignore[union-attr]
                return [*lines[: i + 1], f"{indent}ssl-default-bind-curves {value}", *lines[i + 1 :]]
        raise PatchRejected("no global section found: add 'global' to haproxy.cfg first")
    name = {"postfix": "tls_eecdh_auto_curves", "dovecot": "ssl_curve_list"}[kind]
    out = list(lines)
    idx = len(out)
    while idx > 0 and out[idx - 1] == "":
        idx -= 1
    out.insert(idx, f"{name} = {value}")
    return out
