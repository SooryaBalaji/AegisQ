"""An honest Shor demonstration: order finding for N = 15, a = 7.

N = 15 is a toy. The modular-multiplication circuit below is the standard
"compiled" textbook version: its swap/X pattern was derived knowing the
answer, as were many past hardware "demonstrations" on 15. The demo shows the
algorithm's structure (phase estimation -> period -> factors), not a threat.
"""

from __future__ import annotations

import math
from fractions import Fraction
from typing import Any

DISCLAIMER = (
    "N = 15 is a toy. This circuit hard-codes multiplication by 7 mod 15 as a fixed permutation, which is only "
    "possible because the answer is already known; many past hardware 'demonstrations' on 15 used the same "
    "shortcut. Breaking X25519 needs ~1,200-1,450 error-corrected logical qubits; today's devices have none at "
    "that scale."
)


def _c_amod15(a: int, power: int) -> Any:
    from qiskit import QuantumCircuit

    if a not in (2, 4, 7, 8, 11, 13):
        raise ValueError("a must be coprime with 15 and not 1 or 14")
    u = QuantumCircuit(4)
    for _ in range(power % 4 if a in (2, 7, 8, 13) else power % 2):  # order of a divides 4
        if a in (2, 13):
            u.swap(2, 3)
            u.swap(1, 2)
            u.swap(0, 1)
        if a in (7, 8):
            u.swap(0, 1)
            u.swap(1, 2)
            u.swap(2, 3)
        if a in (4, 11):
            u.swap(1, 3)
            u.swap(0, 2)
        if a in (7, 11, 13):
            for q in range(4):
                u.x(q)
    gate = u.to_gate()
    gate.name = f"{a}^{power} mod 15"
    return gate.control()


def _iqft(n: int) -> Any:
    from qiskit import QuantumCircuit

    qc = QuantumCircuit(n, name="QFT†")
    for q in range(n // 2):
        qc.swap(q, n - q - 1)
    for j in range(n):
        for m in range(j):
            qc.cp(-math.pi / float(2 ** (j - m)), m, j)
        qc.h(j)
    return qc


def build_circuit(a: int = 7, n_count: int = 8) -> Any:
    from qiskit import QuantumCircuit

    qc = QuantumCircuit(n_count + 4, n_count)
    qc.h(range(n_count))
    qc.x(n_count)  # work register starts in |1>
    for q in range(n_count):
        qc.append(_c_amod15(a, 2**q), [q, *range(n_count, n_count + 4)])
    qc.append(_iqft(n_count).to_gate(), range(n_count))
    qc.measure(range(n_count), range(n_count))
    return qc


def interpret(counts: dict[str, int], a: int = 7, n_count: int = 8, big_n: int = 15) -> dict[str, Any]:
    """Turn measured phases into period guesses and factors with continued fractions."""
    total = sum(counts.values())
    rows = []
    found_r = None
    factors: list[int] = []
    for bitstring, c in sorted(counts.items(), key=lambda kv: -kv[1]):
        phase = int(bitstring, 2) / 2**n_count
        frac = Fraction(phase).limit_denominator(big_n)
        r = frac.denominator
        ok = pow(a, r, big_n) == 1
        row: dict[str, Any] = {
            "bits": bitstring,
            "count": c,
            "share": round(c / total, 4),
            "phase": phase,
            "fraction": f"{frac.numerator}/{frac.denominator}",
            "r": r,
            "valid_period": ok,
        }
        if ok and r % 2 == 0 and found_r is None:
            g1, g2 = math.gcd(pow(a, r // 2) - 1, big_n), math.gcd(pow(a, r // 2) + 1, big_n)
            nontrivial = sorted({g for g in (g1, g2) if 1 < g < big_n})
            if nontrivial:
                found_r, factors = r, nontrivial
        rows.append(row)
    return {
        "N": big_n,
        "a": a,
        "counting_qubits": n_count,
        "shots": total,
        "outcomes": rows[:16],
        "period": found_r,
        "factors": factors,
        "disclaimer": DISCLAIMER,
    }


def run(a: int = 7, n_count: int = 8, shots: int = 2048, backend: str = "aer") -> dict[str, Any]:
    from qiskit import transpile

    qc = build_circuit(a, n_count)
    if backend == "aer":
        from qiskit_aer import AerSimulator

        sim = AerSimulator()
        counts = sim.run(transpile(qc, sim), shots=shots).result().get_counts()
        out = interpret(counts, a, n_count)
        out["backend"] = "aer_simulator (noiseless)"
        out["job_id"] = None
        return out
    import warnings

    from qiskit.transpiler import generate_preset_pass_manager
    from qiskit_ibm_runtime import SamplerV2 as Sampler

    from aegisq.entropy.qrng import ibm_service

    service = ibm_service()  # QISKIT_IBM_TOKEN from the environment / .env, else a saved account
    dev = service.backend(backend) if backend != "ibm" else service.least_busy(operational=True, simulator=False)
    isa = generate_preset_pass_manager(backend=dev, optimization_level=3).run(qc)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        job = Sampler(mode=dev).run([isa], shots=shots)
    counts = job.result()[0].data.c.get_counts()
    out = interpret(counts, a, n_count)
    out["backend"] = dev.name
    out["job_id"] = job.job_id()
    out["note"] = "Hardware result shown as measured, noise included."
    return out
