import math

import numpy as np
import pytest

from aegisq.entropy import analysis as a
from aegisq.entropy import qrng
from aegisq.entropy.shor import interpret


def test_nist_sp800_22_reference_vectors() -> None:
    bits = np.array([int(c) for c in "1011010101"], dtype=np.uint8)
    assert a.monobit_test(bits)["p_value"] == pytest.approx(0.527089, abs=1e-6)
    bits = np.array([int(c) for c in "1001101011"], dtype=np.uint8)
    assert a.runs_test(bits)["p_value"] == pytest.approx(0.147232, abs=1e-6)
    assert a.runs_test(np.ones(100, dtype=np.uint8))["pass"] is False


def test_mcv_min_entropy() -> None:
    h, p_hat, p_u = a.mcv_min_entropy(np.array([1] * 6000 + [0] * 4000))
    assert p_hat == 0.6
    assert p_u == pytest.approx(0.6 + 2.576 * math.sqrt(0.24 / 9999))
    assert h == pytest.approx(-math.log2(p_u))
    assert a.mcv_min_entropy(np.zeros(50))[0] == 0.0
    with pytest.raises(a.EntropyError):
        a.mcv_min_entropy(np.array([1]))


def test_spec_output_length() -> None:
    assert a.output_length(10_000, 0.94, 64) == 9272


@pytest.mark.parametrize(("n", "m"), [(1, 1), (17, 5), (64, 64), (500, 300), (2048, 1500)])
def test_toeplitz_fft_matches_naive(n: int, m: int) -> None:
    rng = np.random.default_rng(n * 1000 + m)
    seed = rng.integers(0, 2, n + m - 1).astype(np.uint8)
    x = rng.integers(0, 2, n).astype(np.uint8)
    assert np.array_equal(a.gf2_toeplitz_matvec(seed, x, m), a.gf2_toeplitz_matvec_naive(seed, x, m))


def test_toeplitz_is_linear_over_gf2() -> None:
    rng = np.random.default_rng(3)
    seed = rng.integers(0, 2, 999 + 400).astype(np.uint8)
    x, y = (rng.integers(0, 2, 1000).astype(np.uint8) for _ in range(2))
    f = lambda v: a.gf2_toeplitz_matvec(seed, v, 400)  # noqa: E731
    assert np.array_equal(f(x ^ y), f(x) ^ f(y))


def test_extraction_shapes_and_errors() -> None:
    raw = np.random.default_rng(0).integers(0, 2, 25_000).astype(np.uint8)
    ext = a.toeplitz_extract(raw, 0.94)
    assert ext.blocks == 2 and ext.block_out == 9272 and ext.bits.size == 18_544 and ext.discarded_bits == 5000
    with pytest.raises(a.EntropyError):
        a.toeplitz_extract(raw, 0.01)  # no output at this h
    with pytest.raises(a.EntropyError):
        a.toeplitz_extract(raw[:100], 0.9)
    with pytest.raises(a.EntropyError):
        a.toeplitz_extract(raw, 1.5)
    with pytest.raises(a.EntropyError):
        a.gf2_toeplitz_matvec(np.zeros(5, np.uint8), np.zeros(4, np.uint8), 3)


def test_mix_key() -> None:
    bits = np.ones(256, dtype=np.uint8)
    k1 = a.mix_key(bits, local=b"\x00" * 32)
    assert len(k1) == 32 and k1 == a.mix_key(bits, local=b"\x00" * 32)
    assert k1 != a.mix_key(bits, local=b"\x01" * 32)
    assert len(a.mix_key(bits)) == 32
    with pytest.raises(a.EntropyError):
        a.mix_key(bits, local=b"short")


def synthetic_run(shots: int = 4000, nq: int = 8, bias: float = 0.47) -> a.EntropyRun:
    rng = np.random.default_rng(42)
    raw = (rng.random((shots, nq)) < bias).astype(np.uint8)
    cal0 = (rng.random((shots, nq)) < 0.01).astype(np.uint8)
    cal1 = (rng.random((shots, nq)) > 0.03).astype(np.uint8)
    return a.EntropyRun(raw, cal0, cal1, list(range(nq)), "test", "synthetic", None, "now", True)


def test_analyze_summary() -> None:
    summary, ext, key = a.analyze(synthetic_run(), block=4000)
    assert summary["h_min"] < 1 and summary["simulated"] and "warning" in summary
    assert summary["readout_error_p01"][0] == pytest.approx(0.01, abs=0.01)
    assert summary["readout_error_p10"][0] == pytest.approx(0.03, abs=0.01)
    assert all(b < 0 for b in summary["bias"])
    assert len(summary["correlation_matrix"]) == 8 and summary["noise_band"] == pytest.approx(1.96 / math.sqrt(4000))
    assert summary["extracted_bits"] == ext.bits.size and len(key) == 32
    assert summary["key_fingerprint_sha256"] != key.hex()[:16]  # fingerprint is a hash, never the key
    assert {g["claim"] for g in summary["guarantees"]} >= {"Bits are secret from IBM"}


def test_run_validation() -> None:
    run = synthetic_run()
    run.raw = run.raw[:50]
    with pytest.raises(a.EntropyError):
        run.validate()
    run = synthetic_run()
    run.cal0 = run.cal0[:, :3]
    with pytest.raises(a.EntropyError):
        run.validate()


def test_save_load_roundtrip(tmp_path) -> None:
    run = synthetic_run()
    p = tmp_path / "run.json"
    qrng.save_run(run, p)
    back = qrng.load_run(p)
    assert np.array_equal(back.raw, run.raw) and np.array_equal(back.cal1, run.cal1)
    assert back.qubits == run.qubits and back.simulated and back.source == "file:test"
    p.write_text('{"format": "other"}')
    with pytest.raises(a.EntropyError):
        qrng.load_run(p)


def test_bitstring_order() -> None:
    # Qiskit prints clbit 0 on the right
    arr = qrng.bitstrings_to_array(["001", "100"], 3)
    assert arr.tolist() == [[1, 0, 0], [0, 0, 1]]
    with pytest.raises(a.EntropyError):
        qrng.bitstrings_to_array([], 3)


def test_shor_interpret() -> None:
    counts = {"00000000": 250, "01000000": 250, "10000000": 250, "11000000": 250}
    out = interpret(counts)
    assert out["period"] == 4 and out["factors"] == [3, 5]
    assert "toy" in out["disclaimer"]


@pytest.mark.quantum
def test_shor_on_simulator() -> None:
    from aegisq.entropy import shor

    out = shor.run(shots=512)
    assert out["period"] == 4 and out["factors"] == [3, 5]


@pytest.mark.quantum
@pytest.mark.parametrize("noise", ["readout", "full"])
def test_qrng_simulated_small(noise: str) -> None:
    run = qrng.run_simulated(n_qubits=4, shots=300, noise=noise)
    assert run.raw.shape == (300, 4) and run.simulated and run.source == "aer"
    assert run.backend.endswith(f"{noise}-noise")
    assert run.cal1.mean() > 0.9 and run.cal0.mean() < 0.1
    with pytest.raises(ValueError):
        qrng.run_simulated(n_qubits=2, shots=100, noise="none")


@pytest.mark.quantum
def test_readout_noise_model_reproduces_device_bias() -> None:
    """Fast mode must keep the device's measured readout bias: compare against the calibration snapshot."""
    from qiskit_ibm_runtime.fake_provider import FakeFez

    fake = FakeFez()
    layout, _ = qrng.select_qubits(fake, 20)
    props = fake.properties()
    run = qrng.run_simulated(n_qubits=20, shots=20_000, noise="readout")
    expected_p01 = np.array([props.qubit_property(q)["prob_meas0_prep1"][0] for q in layout])
    measured_p01 = 1 - run.cal1.mean(axis=0)
    assert np.allclose(measured_p01, expected_p01, atol=0.004)
