import random

import pytest

from aegisq.agent import guardrails as gr
from aegisq.config import AgentConfig
from conftest import NGINX_CONF

POLICY = gr.Policy(AgentConfig().allowed_groups)


def patch_for(curve=None, protocols=None, conf=NGINX_CONF):
    return gr.make_patch(conf, "site.conf", ssl_ecdh_curve=curve, ssl_protocols=protocols)


def test_the_one_line_fix_is_accepted() -> None:
    diff = patch_for("X25519MLKEM768:X25519")
    vp = gr.validate_patch(NGINX_CONF, diff, POLICY)
    assert "ssl_ecdh_curve X25519MLKEM768:X25519;  # set by platform team" in vp.new_text  # comment kept
    assert vp.changes == [
        "- ssl_ecdh_curve X25519:prime256v1;  # set by platform team",
        "+ ssl_ecdh_curve X25519MLKEM768:X25519;  # set by platform team",
    ]
    assert vp.diff_sha256 == gr.sha256_text(diff)
    # everything except that one line is byte-identical
    old, new = NGINX_CONF.split("\n"), vp.new_text.split("\n")
    assert [i for i, (a, b) in enumerate(zip(old, new, strict=True)) if a != b] == [7]


def test_protocols_and_curve_together() -> None:
    conf = NGINX_CONF.replace("TLSv1.2 TLSv1.3", "TLSv1.2")
    vp = gr.validate_patch(conf, patch_for("X25519MLKEM768:X25519", "TLSv1.2 TLSv1.3", conf), POLICY)
    assert gr.current_directives(vp.new_text) == {
        "ssl_ecdh_curve": ["X25519MLKEM768:X25519"],
        "ssl_protocols": ["TLSv1.2 TLSv1.3"],
    }


def test_missing_directive_is_inserted_after_each_cert_key() -> None:
    conf = NGINX_CONF.replace("    ssl_ecdh_curve X25519:prime256v1;  # set by platform team\n", "")
    conf = conf.replace("http {", "http {\n  server {\n    listen 8443 ssl;\n    ssl_certificate_key /k;\n  }")
    vp = gr.validate_patch(conf, patch_for("X25519MLKEM768:X25519", conf=conf), POLICY)
    assert vp.new_text.count("ssl_ecdh_curve X25519MLKEM768:X25519;") == 2
    with pytest.raises(gr.PatchRejected, match="ssl_certificate_key"):
        patch_for("X25519MLKEM768:X25519", conf="events {}\nhttp { server { listen 80; } }\n")


def test_crlf_and_no_trailing_newline() -> None:
    conf = NGINX_CONF.rstrip("\n")
    gr.validate_patch(conf, patch_for("X25519MLKEM768:X25519", conf=conf), POLICY)


@pytest.mark.parametrize(
    ("curve", "protocols", "msg"),
    [
        ("X25519", None, "post-quantum hybrid"),
        ("X25519:X25519MLKEM768", None, "must come first"),
        ("X25519MLKEM768", None, "classical fallback"),
        ("X25519MLKEM768:X25519:X25519", None, "listed twice"),
        ("X25519MLKEM768:brainpoolP256r1", None, "not in the allowed list"),
        ("X25519Kyber768Draft00:X25519", None, "not in the allowed list"),
        ("X25519MLKEM768::X25519", None, "empty group"),
        ("X25519MLKEM768:X25519", "TLSv1.2", "TLSv1.3 is required"),
        ("X25519MLKEM768:X25519", "TLSv1 TLSv1.3", "deprecated"),
        ("X25519MLKEM768:X25519", "SSLv3 TLSv1.3", "deprecated"),
        ("X25519MLKEM768:X25519", "TLSv1.3 TLSv1.4", "unknown protocol"),
        ("X25519MLKEM768:X25519", "TLSv1.3 TLSv1.3", "twice"),
    ],
)
def test_policy_violations(curve: str, protocols: str | None, msg: str) -> None:
    with pytest.raises(gr.PatchRejected, match=msg):
        gr.validate_patch(NGINX_CONF, patch_for(curve, protocols), POLICY)


def test_tls13_only_policy() -> None:
    pol = gr.Policy(AgentConfig().allowed_groups, min_tls_version="TLSv1.3")
    conf = NGINX_CONF.replace("TLSv1.2 TLSv1.3", "TLSv1.2")
    with pytest.raises(gr.PatchRejected, match="forbids TLSv1.2"):
        gr.validate_patch(conf, patch_for("X25519MLKEM768:X25519", "TLSv1.2 TLSv1.3", conf), pol)
    gr.validate_patch(conf, patch_for("X25519MLKEM768:X25519", "TLSv1.3", conf), pol)
    pol2 = gr.Policy(AgentConfig().allowed_groups, require_classical_fallback=False)
    gr.validate_patch(NGINX_CONF, patch_for("X25519MLKEM768"), pol2)


GOOD = patch_for("X25519MLKEM768:X25519")


@pytest.mark.parametrize(
    "evil",
    [
        # smuggle a second directive onto the allowed line
        GOOD.replace("X25519MLKEM768:X25519;  #", "X25519MLKEM768:X25519; include /etc/shadow;  #"),
        GOOD.replace("X25519MLKEM768:X25519;  #", "X25519MLKEM768:X25519; } server { listen 9; #"),
        GOOD.replace("+    ssl_ecdh_curve X25519MLKEM768:X25519;", "+    ssl_ecdh_curve $evil;"),
        GOOD.replace("+    ssl_ecdh_curve X25519MLKEM768:X25519;", "+    ssl_ecdh_curve 'X25519MLKEM768:X25519';"),
        GOOD.replace("+    ssl_ecdh_curve X25519MLKEM768:X25519;", r"+    ssl_ecdh_curve X25519MLKEM768:X25519\;"),
        # change a different directive
        GOOD.replace("+    ssl_ecdh_curve", "+    ssl_ciphers"),
        GOOD.replace(
            "+    ssl_ecdh_curve X25519MLKEM768:X25519;  # set by platform team",
            "+    ssl_ecdh_curve X25519MLKEM768:X25519;  # set by platform team\n+    return 301 https://evil;",
        ),
        # a directive hidden behind a comment marker or other prefix
        GOOD.replace("+    ssl_ecdh_curve", "+    #ssl_ecdh_curve"),
        GOOD.replace("+    ssl_ecdh_curve", "+    xssl_ecdh_curve"),
    ],
)
def test_injection_attempts_are_refused(evil: str) -> None:
    with pytest.raises(gr.PatchRejected):
        gr.validate_patch(NGINX_CONF, evil, POLICY)


def test_structural_refusals() -> None:
    with pytest.raises(gr.PatchRejected, match="no hunks"):
        gr.validate_patch(NGINX_CONF, "--- a\n+++ b\n", POLICY)
    with pytest.raises(gr.PatchRejected, match="more than one file|unexpected diff line"):
        gr.validate_patch(NGINX_CONF, GOOD + GOOD, POLICY)
    with pytest.raises(gr.PatchRejected, match="counts do not match"):
        gr.validate_patch(NGINX_CONF, GOOD.replace("@@ -5,7 +5,7 @@", "@@ -5,7 +5,9 @@"), POLICY)
    with pytest.raises(gr.PatchRejected, match="context mismatch"):
        gr.validate_patch(NGINX_CONF.replace("server.key", "other.key"), GOOD, POLICY)
    with pytest.raises(gr.PatchRejected, match="context mismatch|beyond"):
        gr.validate_patch(NGINX_CONF, GOOD.replace("@@ -5,7 +5,7 @@", "@@ -60,7 +60,7 @@"), POLICY)
    deletion = "@@ -8,1 +8,0 @@\n-    ssl_ecdh_curve X25519:prime256v1;  # set by platform team\n"
    with pytest.raises(gr.PatchRejected, match="without replacing"):
        gr.validate_patch(NGINX_CONF, deletion, POLICY)
    with pytest.raises(gr.PatchRejected, match="NUL"):
        gr.validate_patch(NGINX_CONF, GOOD + "\x00", POLICY)
    with pytest.raises(gr.PatchRejected, match="too large"):
        gr.validate_patch(NGINX_CONF, "x" * (gr.MAX_DIFF_BYTES + 1), POLICY)
    with pytest.raises(gr.PatchRejected, match="already has"):
        patch_for("X25519:prime256v1")
    with pytest.raises(gr.PatchRejected, match="may not contain"):
        patch_for("X25519MLKEM768:X25519; include x")
    with pytest.raises(gr.PatchRejected, match="nothing to change"):
        patch_for()


def test_hand_written_diff_without_headers_works() -> None:
    diff = (
        "@@ -8 +8 @@\n"
        "-    ssl_ecdh_curve X25519:prime256v1;  # set by platform team\n"
        "+    ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;\n"
    )
    vp = gr.validate_patch(NGINX_CONF, diff, POLICY)
    assert "X25519MLKEM768:X25519:prime256v1;" in vp.new_text


def test_mutation_fuzz_never_lets_other_lines_change() -> None:
    """Randomly corrupt a valid diff thousands of times. Whatever is accepted may only differ from the
    original config on ssl_ecdh_curve / ssl_protocols lines."""
    rng = random.Random(7)
    lines = GOOD.split("\n")
    alphabet = " +-@,;{}#$abcdefTLSv1.23X25519MLKEM768:ssl_ecdh_curveprotocols\\'\"\t"
    accepted = 0
    for _ in range(4000):
        mutated = list(lines)
        for _ in range(rng.randint(1, 4)):
            i = rng.randrange(len(mutated))
            op = rng.random()
            line = mutated[i]
            if op < 0.4 and line:
                j = rng.randrange(len(line))
                mutated[i] = line[:j] + rng.choice(alphabet) + line[j + 1 :]
            elif op < 0.6:
                mutated.insert(i, rng.choice(["+" + line[1:], "-" + line[1:], " " + line[1:], line]))
            elif op < 0.8:
                del mutated[i]
            else:
                mutated[i] = rng.choice("+- ") + line[1:]
        try:
            vp = gr.validate_patch(NGINX_CONF, "\n".join(mutated), POLICY)
        except gr.PatchRejected:
            continue
        accepted += 1
        a, b = NGINX_CONF.split("\n"), vp.new_text.split("\n")
        import difflib

        for op, i1, i2, j1, j2 in difflib.SequenceMatcher(a=a, b=b, autojunk=False).get_opcodes():
            if op != "equal":
                for line in a[i1:i2] + b[j1:j2]:
                    assert gr.DIRECTIVE_RE.match(line), line
    assert accepted < 4000
