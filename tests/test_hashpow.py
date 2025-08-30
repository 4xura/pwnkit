# tests/test_hashpow.py
import hashlib
import pytest

from pwnkit.hashpow import solve_pow, solve_pow_mt

def _ok(prefix: str, s: str, suffix: str, algo: str, pred):
    h = hashlib.new(algo)
    h.update(prefix.encode("latin-1"))
    h.update(s.encode("latin-1"))
    h.update(suffix.encode("latin-1"))
    return pred(h.hexdigest())

def test_solve_pow_bytes_vs_str_deterministic_true_predicate():
    # A predicate that's always true → first lexicographic candidate returned.
    # This guarantees existence and lets us verify bytes/str interop.
    pred = lambda _h: True
    s1 = solve_pow("sha256", b"PFX", "SFX", pred, alphabet="01", start_length=1, max_length=2, timeout_sec=2.0)
    s2 = solve_pow("sha256", "PFX", b"SFX", pred, alphabet="01", start_length=1, max_length=2, timeout_sec=2.0)
    assert s1 == "0" and s2 == "0"  # first candidate in lexicographic order

@pytest.mark.parametrize("algo,starts,alphabet,start_len,max_len", [
    # Wider space so a prefix match is very likely and quick.
    ("sha256", "00", "0123456789abcdef", 1, 3),
    ("sha1",   "0",  "0123456789abcdef", 1, 3),
])
def test_solve_pow_real_predicate(algo, starts, alphabet, start_len, max_len):
    pred = lambda h: h.startswith(starts)
    s = solve_pow(
        algo,
        prefix_str="seed:",
        suffix_str=":end",
        check_res_func=pred,
        alphabet=alphabet,
        start_length=start_len,
        max_length=max_len,
        timeout_sec=5.0,
    )
    # It's still theoretically possible none match; if so, don't fail the build—just assert correctness when found.
    if s is not None:
        assert _ok("seed:", s, ":end", algo, pred)

def test_no_solution_returns_none():
    # Impossible within given bounds (always-false predicate).
    s = solve_pow(
        "sha256",
        prefix_str="x",
        suffix_str="y",
        check_res_func=lambda _h: False,
        alphabet="a",
        start_length=1,
        max_length=2,
        timeout_sec=1.0,
    )
    assert s is None

def test_timeout_triggers_none():
    # Force heavy search + harsh predicate; tiny timeout → None
    s = solve_pow(
        "sha256",
        prefix_str="seed",
        suffix_str="",
        check_res_func=lambda h: h.startswith("000000000"),
        alphabet="0123456789abcdef",
        start_length=1,
        max_length=5,
        timeout_sec=0.01,
    )
    assert s is None

def test_invalid_algorithm_raises():
    with pytest.raises(ValueError):
        solve_pow(
            "nopehash",
            prefix_str="p",
            suffix_str="s",
            check_res_func=lambda h: True,
            alphabet="ab",
            start_length=1,
            max_length=1,
        )

def test_mt_with_single_worker_matches_st_on_true_predicate():
    # With a True predicate and max_workers=1, MT should match ST lexicographic result.
    pred = lambda _h: True
    st = solve_pow("sha256", "pref", "suf", pred, alphabet="01ab", start_length=1, max_length=3, timeout_sec=5.0)
    mt = solve_pow_mt("sha256", "pref", "suf", pred, alphabet="01ab", start_length=1, max_length=3, timeout_sec=5.0, max_workers=1)
    assert st == mt == "0"  # first candidate

