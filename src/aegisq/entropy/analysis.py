"""Classical post-processing for quantum random bits.

Pipeline: readout calibration -> bias, correlation and autocorrelation checks ->
conservative min-entropy bound (NIST SP 800-90B most-common-value estimate,
99% upper confidence bound, minimum over qubits) -> seeded Toeplitz extractor
(leftover hash lemma, m = floor(n*h) - 2*log2(1/eps)) -> statistical tests side
by side with os.urandom -> HKDF-SHA256 mix with 32 local bytes so the final key
is never weaker than a normal one.
"""

from __future__ import annotations

import hashlib
import math
import os
from dataclasses import dataclass, field
from typing import Any

import numpy as np
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

Z99 = 2.576  # two-sided 99% normal quantile, as in SP 800-90B §6.3.1


class EntropyError(ValueError):
    pass


# ------------------------------------------------------------ estimates ---


def mcv_min_entropy(bits: np.ndarray) -> tuple[float, float, float]:
    """SP 800-90B §6.3.1 most-common-value estimate for a binary sample.

    Returns (h, p_hat, p_upper) where h = -log2(p_upper) bits per sample.
    """
    b = np.asarray(bits).ravel()
    n = b.size
    if n < 2:
        raise EntropyError("need at least 2 samples")
    ones = float(np.count_nonzero(b))
    p_hat = max(ones, n - ones) / n
    p_u = min(1.0, p_hat + Z99 * math.sqrt(p_hat * (1.0 - p_hat) / (n - 1)))
    return (-math.log2(p_u) if p_u > 0 else 0.0), p_hat, p_u


def per_qubit_min_entropy(raw: np.ndarray) -> np.ndarray:
    return np.array([mcv_min_entropy(raw[:, q])[0] for q in range(raw.shape[1])])


def readout_errors(cal0: np.ndarray, cal1: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """P(read 1 | prepared 0) and P(read 0 | prepared 1) per qubit, from calibration shots in the same job."""
    p01 = cal0.mean(axis=0)
    p10 = 1.0 - cal1.mean(axis=0)
    return p01, p10


def correlation_matrix(raw: np.ndarray) -> np.ndarray:
    x = raw.astype(np.float64)
    x -= x.mean(axis=0)
    sd = x.std(axis=0)
    with np.errstate(invalid="ignore", divide="ignore"):
        c = (x.T @ x) / x.shape[0] / np.outer(sd, sd)
    c[~np.isfinite(c)] = 0.0
    np.fill_diagonal(c, 1.0)
    return c


def lag1_autocorrelation(raw: np.ndarray) -> np.ndarray:
    x = raw.astype(np.float64)
    x -= x.mean(axis=0)
    num = (x[1:] * x[:-1]).sum(axis=0)
    den = (x * x).sum(axis=0)
    with np.errstate(invalid="ignore", divide="ignore"):
        r = num / den
    r[~np.isfinite(r)] = 0.0
    return r


def noise_band(n: int, z: float = 1.96) -> float:
    """|r| below this is consistent with chance for n samples (about ±0.02 at n = 10,000)."""
    return z / math.sqrt(n)


# ------------------------------------------------------------ extractor ---


def output_length(n: int, h: float, eps_bits: int) -> int:
    return math.floor(n * h) - 2 * eps_bits


def gf2_toeplitz_matvec(seed: np.ndarray, x: np.ndarray, m: int) -> np.ndarray:
    """y = T x over GF(2), with T[i, j] = seed[i - j + n - 1] (an m x n Toeplitz matrix).

    Computed as a convolution with an FFT. Every entry of the integer product is
    at most n, far below float64's exact-integer range, and the result is
    checked to be integral before reducing mod 2, so a rounding error cannot
    silently corrupt the output.
    """
    n = x.size
    if seed.size != n + m - 1:
        raise EntropyError("seed must have n + m - 1 bits")
    size = 1 << (seed.size + n - 1).bit_length()
    prod = np.fft.irfft(np.fft.rfft(seed.astype(np.float64), size) * np.fft.rfft(x.astype(np.float64), size), size)
    y = prod[n - 1 : n - 1 + m]
    r = np.rint(y)
    if np.max(np.abs(y - r), initial=0.0) > 0.25:
        raise EntropyError("FFT precision check failed")
    return (r.astype(np.int64) & 1).astype(np.uint8)


def gf2_toeplitz_matvec_naive(seed: np.ndarray, x: np.ndarray, m: int) -> np.ndarray:
    """Reference implementation for tests (O(m n))."""
    n = x.size
    idx = np.arange(m)[:, None] - np.arange(n)[None, :] + n - 1
    t = seed[idx]
    return ((t.astype(np.int64) @ x.astype(np.int64)) & 1).astype(np.uint8)


@dataclass
class Extraction:
    bits: np.ndarray
    block_in: int
    block_out: int
    blocks: int
    h: float
    eps_bits: int
    seed_sha256: str
    discarded_bits: int


def toeplitz_extract(
    raw_bits: np.ndarray, h: float, block: int = 10_000, eps_bits: int = 64, seed: np.ndarray | None = None
) -> Extraction:
    raw = np.asarray(raw_bits, dtype=np.uint8).ravel()
    if not 0 < h <= 1:
        raise EntropyError(f"min-entropy per bit must be in (0, 1], got {h}")
    m = output_length(block, h, eps_bits)
    if m <= 0:
        raise EntropyError(f"block of {block} bits at h={h:.4f} yields no output at eps=2^-{eps_bits}")
    blocks = raw.size // block
    if blocks == 0:
        raise EntropyError(f"need at least {block} raw bits, have {raw.size}")
    if seed is None:
        nbytes = (block + m - 1 + 7) // 8
        seed = np.unpackbits(np.frombuffer(os.urandom(nbytes), dtype=np.uint8))[: block + m - 1]
    out = np.empty(blocks * m, dtype=np.uint8)
    for b in range(blocks):
        out[b * m : (b + 1) * m] = gf2_toeplitz_matvec(seed, raw[b * block : (b + 1) * block], m)
    return Extraction(
        bits=out,
        block_in=block,
        block_out=m,
        blocks=blocks,
        h=h,
        eps_bits=eps_bits,
        seed_sha256=hashlib.sha256(np.packbits(seed).tobytes()).hexdigest(),
        discarded_bits=raw.size - blocks * block,
    )


# ---------------------------------------------------------------- tests ---


def monobit_test(bits: np.ndarray) -> dict[str, Any]:
    """NIST SP 800-22 §2.1 frequency (monobit) test."""
    b = np.asarray(bits).ravel()
    n = b.size
    s = int(2 * np.count_nonzero(b) - n)
    s_obs = abs(s) / math.sqrt(n)
    p = math.erfc(s_obs / math.sqrt(2))
    return {"test": "monobit", "n": n, "ones_fraction": round(float(b.mean()), 6), "p_value": p, "pass": p >= 0.01}


def runs_test(bits: np.ndarray) -> dict[str, Any]:
    """NIST SP 800-22 §2.3 runs test (with its frequency prerequisite)."""
    b = np.asarray(bits).ravel().astype(np.int8)
    n = b.size
    pi = float(b.mean())
    if abs(pi - 0.5) >= 2 / math.sqrt(n):
        return {"test": "runs", "n": n, "p_value": 0.0, "pass": False, "note": "frequency prerequisite failed"}
    v_obs = 1 + int(np.count_nonzero(b[1:] != b[:-1]))
    num = abs(v_obs - 2 * n * pi * (1 - pi))
    p = math.erfc(num / (2 * math.sqrt(2 * n) * pi * (1 - pi)))
    return {"test": "runs", "n": n, "runs": v_obs, "p_value": p, "pass": p >= 0.01}


def side_by_side(extracted: np.ndarray) -> dict[str, Any]:
    local = np.unpackbits(np.frombuffer(os.urandom((extracted.size + 7) // 8), dtype=np.uint8))[: extracted.size]
    return {
        "extracted": [monobit_test(extracted), runs_test(extracted)],
        "os_urandom": [monobit_test(local), runs_test(local)],
        "note": "Passing means no detected flaw, not proof of randomness.",
    }


# ------------------------------------------------------------------ mix ---


def mix_key(
    extracted: np.ndarray, length: int = 32, info: bytes = b"aegisq-pq-key-v1", local: bytes | None = None
) -> bytes:
    """HKDF-SHA256(extracted bytes || 32 bytes of os.urandom). Secure if either input is."""
    local = os.urandom(32) if local is None else local
    if len(local) < 32:
        raise EntropyError("need at least 32 local random bytes")
    ikm = np.packbits(np.asarray(extracted, dtype=np.uint8)).tobytes() + local
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(ikm)


# ------------------------------------------------------------- analysis ---


@dataclass
class EntropyRun:
    raw: np.ndarray  # (shots, qubits) uint8
    cal0: np.ndarray  # (shots, qubits) prepared |0>
    cal1: np.ndarray  # (shots, qubits) prepared |1>
    qubits: list[int]
    source: str  # ibm | aer | file
    backend: str
    job_id: str | None
    created: str
    simulated: bool
    reported_readout_error: list[float] = field(default_factory=list)

    def validate(self) -> None:
        for name, a in (("raw", self.raw), ("cal0", self.cal0), ("cal1", self.cal1)):
            if a.ndim != 2 or a.shape[1] != len(self.qubits):
                raise EntropyError(f"{name} must be (shots, {len(self.qubits)})")
            if a.size and (a.min() < 0 or a.max() > 1):
                raise EntropyError(f"{name} must contain only 0/1")
        if self.raw.shape[0] < 100:
            raise EntropyError("need at least 100 shots")


def analyze(run: EntropyRun, block: int = 10_000, eps_bits: int = 64) -> tuple[dict[str, Any], Extraction, bytes]:
    run.validate()
    p01, p10 = readout_errors(run.cal0, run.cal1)
    bias = run.raw.mean(axis=0) - 0.5
    corr = correlation_matrix(run.raw)
    off = corr[~np.eye(corr.shape[0], dtype=bool)]
    ac = lag1_autocorrelation(run.raw)
    hq = per_qubit_min_entropy(run.raw)
    h = float(hq.min())
    band = noise_band(run.raw.shape[0])
    ext = toeplitz_extract(run.raw.ravel(), h, block=block, eps_bits=eps_bits)
    tests = side_by_side(ext.bits)
    key = mix_key(ext.bits)
    summary: dict[str, Any] = {
        "source": run.source,
        "backend": run.backend,
        "job_id": run.job_id,
        "created": run.created,
        "simulated": run.simulated,
        "qubits": run.qubits,
        "shots": int(run.raw.shape[0]),
        "raw_bits": int(run.raw.size),
        "readout_error_p01": p01.round(5).tolist(),
        "readout_error_p10": p10.round(5).tolist(),
        "reported_readout_error": run.reported_readout_error,
        "bias": bias.round(5).tolist(),
        "min_entropy_per_qubit": hq.round(5).tolist(),
        "h_min": h,
        "worst_qubit": run.qubits[int(np.argmin(hq))],
        "correlation_max_abs_offdiag": float(np.abs(off).max()) if off.size else 0.0,
        "correlation_outside_band": int((np.abs(off) > band).sum() // 2),
        "correlation_matrix": corr.round(4).tolist(),
        "autocorr_lag1": ac.round(5).tolist(),
        "autocorr_outside_band": int((np.abs(ac) > band).sum()),
        "noise_band": band,
        "extractor": {
            "type": "Toeplitz (seeded, GF(2))",
            "block_in": ext.block_in,
            "block_out": ext.block_out,
            "blocks": ext.blocks,
            "eps_bits": ext.eps_bits,
            "seed_sha256": ext.seed_sha256,
            "discarded_bits": ext.discarded_bits,
        },
        "extracted_bits": int(ext.bits.size),
        "eps_bits": eps_bits,
        "tests": tests,
        "key_fingerprint_sha256": hashlib.sha256(key).hexdigest()[:16],
        "guarantees": [
            {
                "claim": "Bits are unpredictable to an outside attacker",
                "status": "Yes, with a quantified bound",
                "why": f"Measured min-entropy plus Toeplitz extraction with ε = 2^-{eps_bits}",
            },
            {
                "claim": "Bits are secret from IBM",
                "status": "No",
                "why": "Generated in IBM's cloud; the HKDF mix with local randomness covers this",
            },
            {
                "claim": "Bits are certified device-independent",
                "status": "No",
                "why": "Requires a certified randomness protocol, a separate research result",
            },
            {
                "claim": "The final key is at least as strong as a normal key",
                "status": "Yes",
                "why": "HKDF mixing with 32 bytes of os.urandom",
            },
        ],
    }
    if run.simulated:
        summary["warning"] = (
            "SIMULATED RUN: a simulator draws its 'measurements' from a classical pseudo-random generator. "
            "This exercises the pipeline only; it is not quantum randomness."
        )
    return summary, ext, key
