"""Run the QRNG job: on IBM Quantum hardware, or simulated (clearly labelled) for offline testing.

One job carries three circuits: Hadamard + measure on the chosen qubits, and
two calibration circuits (all |0>, all |1>) that measure each qubit's readout
error directly, in the same calibration window as the random bits.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import os
import warnings
from pathlib import Path
from typing import Any

import numpy as np

from aegisq.entropy.analysis import EntropyError, EntropyRun
from aegisq.workspace import atomic_write


class QuantumUnavailable(RuntimeError):
    pass


def _require_qiskit() -> None:
    try:
        import qiskit  # noqa: F401
    except ImportError as e:
        raise QuantumUnavailable("install the quantum extra: pip install 'aegisq[quantum]'") from e


def select_qubits(backend: Any, n: int) -> tuple[list[int], list[float]]:
    """The n qubits with the lowest reported readout error (backend.target['measure'][(q,)].error)."""
    measure = backend.target["measure"]
    errs = []
    for q in range(backend.num_qubits):
        props = measure.get((q,))
        if props is not None and props.error is not None:
            errs.append((float(props.error), q))
    if len(errs) < n:
        raise EntropyError(f"backend has only {len(errs)} calibrated qubits, need {n}")
    errs.sort()
    chosen = errs[:n]
    return [q for _, q in chosen], [e for e, _ in chosen]


def build_circuits(n: int) -> list[Any]:
    from qiskit import ClassicalRegister, QuantumCircuit, QuantumRegister

    circuits = []
    for kind in ("random", "cal0", "cal1"):
        qr, cr = QuantumRegister(n, "q"), ClassicalRegister(n, "c")
        qc = QuantumCircuit(qr, cr, name=f"aegisq-{kind}")
        if kind == "random":
            qc.h(qr)
        elif kind == "cal1":
            qc.x(qr)
        qc.measure(qr, cr)
        circuits.append(qc)
    return circuits


def bitstrings_to_array(bitstrings: list[str], n: int) -> np.ndarray:
    """Qiskit bitstrings put classical bit 0 on the right; return columns in clbit order."""
    if not bitstrings:
        raise EntropyError("job returned no shots")
    arr = np.frombuffer("".join(bitstrings).encode("ascii"), dtype=np.uint8).reshape(len(bitstrings), n) - ord("0")
    if np.max(arr) > 1:
        raise EntropyError("unexpected characters in bitstrings")
    return arr[:, ::-1].astype(np.uint8)


def _execute(backend: Any, sampler: Any, n: int, shots: int, cal_shots: int, layout: list[int]) -> tuple[Any, Any]:
    from qiskit.transpiler import generate_preset_pass_manager

    pm = generate_preset_pass_manager(backend=backend, optimization_level=1, initial_layout=layout)
    isa = [pm.run(c) for c in build_circuits(n)]
    job = sampler.run([(isa[0], None, shots), (isa[1], None, cal_shots), (isa[2], None, cal_shots)])
    return job, job.result()


def ibm_service() -> Any:
    """Connect to IBM Quantum: QISKIT_IBM_TOKEN (+ optional QISKIT_IBM_INSTANCE), else a saved account."""
    try:
        from qiskit_ibm_runtime import QiskitRuntimeService
    except ImportError as e:
        raise QuantumUnavailable("install qiskit-ibm-runtime: pip install 'aegisq[quantum]'") from e
    token = os.environ.get("QISKIT_IBM_TOKEN")
    kwargs: dict[str, Any] = {}
    if token:
        kwargs = {"channel": "ibm_quantum_platform", "token": token}
        if os.environ.get("QISKIT_IBM_INSTANCE"):
            kwargs["instance"] = os.environ["QISKIT_IBM_INSTANCE"]
    try:
        return QiskitRuntimeService(**kwargs)
    except Exception as e:
        raise QuantumUnavailable(f"cannot connect to IBM Quantum (set QISKIT_IBM_TOKEN): {e}") from e


def run_ibm(
    n_qubits: int = 100, shots: int = 10_000, cal_shots: int | None = None, backend_name: str | None = None
) -> EntropyRun:
    """Submit to real IBM hardware. Credentials: a saved QiskitRuntimeService account, or
    QISKIT_IBM_TOKEN (+ optional QISKIT_IBM_INSTANCE) in the environment."""
    _require_qiskit()
    try:
        from qiskit_ibm_runtime import SamplerV2 as Sampler
    except ImportError as e:
        raise QuantumUnavailable("install qiskit-ibm-runtime: pip install 'aegisq[quantum]'") from e
    service = ibm_service()
    backend = (
        service.backend(backend_name)
        if backend_name
        else service.least_busy(operational=True, simulator=False, min_num_qubits=n_qubits)
    )
    layout, errs = select_qubits(backend, n_qubits)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        sampler = Sampler(mode=backend)
    job, result = _execute(backend, sampler, n_qubits, shots, cal_shots or shots, layout)
    return _to_run(result, n_qubits, layout, errs, "ibm", backend.name, job.job_id(), simulated=False)


def readout_noise_model(backend: Any, layout: list[int]) -> Any:
    """A noise model with only each chosen qubit's measured readout errors (asymmetric P(1|0), P(0|1)),
    attached to circuit qubit i for physical qubit layout[i]."""
    from qiskit_aer.noise import NoiseModel, ReadoutError

    props = backend.properties()
    nm = NoiseModel()
    for i, q in enumerate(layout):
        try:
            p10 = float(props.qubit_property(q)["prob_meas1_prep0"][0])
            p01 = float(props.qubit_property(q)["prob_meas0_prep1"][0])
        except (KeyError, TypeError, AttributeError):  # snapshot without the split: use the symmetric figure
            p10 = p01 = float(backend.target["measure"][(q,)].error or 0.0)
        nm.add_readout_error(ReadoutError([[1 - p10, p10], [p01, 1 - p01]]), [i])
    return nm


def run_simulated(
    n_qubits: int = 100,
    shots: int = 10_000,
    cal_shots: int | None = None,
    fake_backend: str = "FakeFez",
    noise: str = "readout",
) -> EntropyRun:
    """Offline run with a real device's calibration snapshot. NOT quantum randomness.

    noise="readout" (default, seconds): the device's per-qubit readout errors, the dominant bias in this
      experiment. The circuits are all Clifford (H, X, measure), so Aer's stabilizer method simulates
      100 qubits exactly and fast.
    noise="full" (about a minute): the full device noise model (gate errors, T1/T2 relaxation) on the
      matrix-product-state method, with the circuits transpiled onto the device.
    All three circuits run in parallel in both modes.
    """
    _require_qiskit()
    try:
        from qiskit_aer import AerSimulator
        from qiskit_aer.primitives import SamplerV2 as AerSampler
        from qiskit_ibm_runtime import fake_provider
    except ImportError as e:
        raise QuantumUnavailable("install qiskit-aer and qiskit-ibm-runtime: pip install 'aegisq[quantum]'") from e
    if noise not in ("readout", "full"):
        raise ValueError("noise must be 'readout' or 'full'")
    cls = getattr(fake_provider, fake_backend, None)
    if cls is None:
        raise QuantumUnavailable(f"unknown fake backend {fake_backend!r}")
    fake = cls()
    layout, errs = select_qubits(fake, n_qubits)
    parallel = {"max_parallel_experiments": 3, "max_parallel_threads": 0}
    if noise == "readout":
        opts = {"method": "stabilizer", "noise_model": readout_noise_model(fake, layout), **parallel}
        sampler = AerSampler(options={"backend_options": opts})
        cal = cal_shots or shots
        circuits = build_circuits(n_qubits)
        result = sampler.run([(circuits[0], None, shots), (circuits[1], None, cal), (circuits[2], None, cal)]).result()
    else:
        sim = AerSimulator.from_backend(fake, method="matrix_product_state", **parallel)
        sampler = AerSampler.from_backend(sim)
        _job, result = _execute(fake, sampler, n_qubits, shots, cal_shots or shots, layout)
    return _to_run(result, n_qubits, layout, errs, "aer", f"aer:{fake.name}:{noise}-noise", None, simulated=True)


def _to_run(
    result: Any,
    n: int,
    layout: list[int],
    errs: list[float],
    source: str,
    backend: str,
    job_id: str | None,
    simulated: bool,
) -> EntropyRun:
    arrays = [bitstrings_to_array(result[i].data.c.get_bitstrings(), n) for i in range(3)]
    run = EntropyRun(
        raw=arrays[0],
        cal0=arrays[1],
        cal1=arrays[2],
        qubits=layout,
        source=source,
        backend=backend,
        job_id=job_id,
        created=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        simulated=simulated,
        reported_readout_error=errs,
    )
    run.validate()
    return run


# --------------------------------------------------------------- storage ---


def _pack(a: np.ndarray) -> dict[str, Any]:
    return {"shape": list(a.shape), "bits_b64": base64.b64encode(np.packbits(a.ravel()).tobytes()).decode()}


def _unpack(d: dict[str, Any]) -> np.ndarray:
    shape = tuple(int(x) for x in d["shape"])
    total = int(np.prod(shape))
    raw = np.frombuffer(base64.b64decode(d["bits_b64"], validate=True), dtype=np.uint8)
    bits = np.unpackbits(raw)
    if bits.size < total:
        raise EntropyError("saved run is truncated")
    return bits[:total].reshape(shape)


def save_run(run: EntropyRun, path: Path) -> None:
    doc = {
        "format": "aegisq-entropy-run/1",
        "source": run.source,
        "backend": run.backend,
        "job_id": run.job_id,
        "created": run.created,
        "simulated": run.simulated,
        "qubits": run.qubits,
        "reported_readout_error": run.reported_readout_error,
        "raw": _pack(run.raw),
        "cal0": _pack(run.cal0),
        "cal1": _pack(run.cal1),
    }
    atomic_write(path, json.dumps(doc))


def load_run(path: Path) -> EntropyRun:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise EntropyError(f"cannot read saved run {path}: {e}") from e
    if doc.get("format") != "aegisq-entropy-run/1":
        raise EntropyError("not a AegisQ entropy run file")
    run = EntropyRun(
        raw=_unpack(doc["raw"]),
        cal0=_unpack(doc["cal0"]),
        cal1=_unpack(doc["cal1"]),
        qubits=[int(q) for q in doc["qubits"]],
        source="file:" + str(doc.get("source")),
        backend=str(doc.get("backend")),
        job_id=doc.get("job_id"),
        created=str(doc.get("created")),
        simulated=bool(doc.get("simulated", True)),
        reported_readout_error=doc.get("reported_readout_error") or [],
    )
    run.validate()
    return run
