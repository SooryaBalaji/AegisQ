"""Patch guardrails. These live in code, not in the prompt: whatever the model writes, only
``ssl_ecdh_curve`` and ``ssl_protocols`` lines can change, and only to values policy allows.

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

from aegisq.crypto_registry import group_by_name

ALLOWED_DIRECTIVES = ("ssl_ecdh_curve", "ssl_protocols")
MAX_DIFF_BYTES = 64 * 1024
MAX_CONFIG_BYTES = 1024 * 1024

# One directive, alone on its line, optional trailing comment. The value may not contain
# ; { } quotes, backslashes, $ or # so a line can never smuggle a second directive or a variable.
DIRECTIVE_RE = re.compile(
    r"^(?P<indent>[ \t]*)(?P<name>ssl_ecdh_curve|ssl_protocols)[ \t]+(?P<value>[^;{}'\"\\$#\r\n]+?)[ \t]*;"
    r"(?P<comment>[ \t]*#[^\r\n]*)?[ \t]*$"
)
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


def _check_value(name: str, value: str, policy: Policy) -> None:
    if name == "ssl_ecdh_curve":
        parts = value.strip().split(":")
        if any(not p for p in parts):
            raise PatchRejected("ssl_ecdh_curve has an empty group")
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
            raise PatchRejected("ssl_ecdh_curve must include a post-quantum hybrid group such as X25519MLKEM768")
        first = group_by_name(parts[0])
        if first is None or not first.pq:
            raise PatchRejected("the post-quantum hybrid group must come first so it is preferred")
        if policy.require_classical_fallback and classical == 0:
            raise PatchRejected("policy requires a classical fallback (e.g. X25519) so older clients still connect")
    elif name == "ssl_protocols":
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
    else:  # pragma: no cover - regex only matches allowed names
        raise PatchRejected(f"directive {name} not allowed")


def _check_line(line: str, policy: Policy) -> str:
    m = DIRECTIVE_RE.match(line)
    if not m:
        raise PatchRejected(f"change outside ssl_ecdh_curve/ssl_protocols refused: {line.strip()[:100]!r}")
    return m.group("name")


def validate_patch(original: str, diff: str, policy: Policy) -> ValidatedPatch:
    if len(original.encode("utf-8")) > MAX_CONFIG_BYTES:
        raise PatchRejected("config too large")
    hunks = parse_unified_diff(diff)
    removed: dict[str, int] = dict.fromkeys(ALLOWED_DIRECTIVES, 0)
    added: dict[str, int] = dict.fromkeys(ALLOWED_DIRECTIVES, 0)
    changes: list[str] = []
    for h in hunks:
        for line in h.lines:
            tag, text = line[:1], line[1:]
            if tag == "-":
                removed[_check_line(text, policy)] += 1
                changes.append(f"- {text.strip()}")
            elif tag == "+":
                name = _check_line(text, policy)
                m = DIRECTIVE_RE.match(text)
                assert m is not None
                _check_value(name, m.group("value"), policy)
                added[name] += 1
                changes.append(f"+ {text.strip()}")
    for d in ALLOWED_DIRECTIVES:
        if removed[d] > added[d]:
            raise PatchRejected(f"patch deletes {d} without replacing it")
    if not any(added.values()):
        raise PatchRejected("patch changes nothing")

    new_text = apply_hunks(original, hunks)
    if new_text == original:
        raise PatchRejected("patch is a no-op")
    _independent_check(original, new_text, policy)
    _check_braces(new_text)
    return ValidatedPatch(diff=diff, new_text=new_text, diff_sha256=sha256_text(diff), changes=changes)


def _independent_check(original: str, new_text: str, policy: Policy) -> None:
    """Re-diff the result with difflib: every changed line must be an allowed directive."""
    a, b = original.split("\n"), new_text.split("\n")
    sm = difflib.SequenceMatcher(a=a, b=b, autojunk=False)
    for op, i1, i2, j1, j2 in sm.get_opcodes():
        if op == "equal":
            continue
        for line in a[i1:i2]:
            _check_line(line, policy)
        for line in b[j1:j2]:
            name = _check_line(line, policy)
            m = DIRECTIVE_RE.match(line)
            assert m is not None
            _check_value(name, m.group("value"), policy)


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
    # Split on "\n" exactly as apply_hunks does, so line numbers agree even without a final newline.
    diff_lines = difflib.unified_diff(
        original.split("\n"), new_text.split("\n"), fromfile=f"a/{filename}", tofile=f"b/{filename}", n=3, lineterm=""
    )
    return "\n".join(diff_lines) + "\n"


def current_directives(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {d: [] for d in ALLOWED_DIRECTIVES}
    for line in text.split("\n"):
        m = DIRECTIVE_RE.match(line)
        if m:
            out[m.group("name")].append(m.group("value").strip())
    return out
