"""E1 + E7 — RFC 8785 (JCS) canonicalization.

Every vector here is copied from the reference implementation's own
``packages/core/__tests__/jcs.test.ts`` so a byte-for-byte match proves the two
implementations canonicalize identically (the top portability risk per
aer-feedback #8). gatehouse uses the Trail of Bits ``rfc8785`` library.
"""

from __future__ import annotations

import pytest

from gatehouse.canonical import CanonicalizationError, jcs_bytes, sha256_hex, sha256_jcs


def canon(obj) -> str:
    return jcs_bytes(obj).decode("utf-8")


# --- E1: ECMAScript Number::toString formatting (the portability risk) --------

def test_number_formatting_matches_ecmascript():
    # From jcs.test.ts: the Appendix-B ordering vector values.
    assert canon(333333333.33333329) == "333333333.3333333"
    assert canon(1e30) == "1e+30"
    assert canon(4.5) == "4.5"
    assert canon(2e-3) == "0.002"
    assert canon(1e-27) == "1e-27"
    assert canon([333333333.33333329, 1e30, 4.5, 2e-3, 1e-27]) == (
        "[333333333.3333333,1e+30,4.5,0.002,1e-27]"
    )


def test_negative_zero_serializes_as_zero():
    assert canon(-0.0) == "0"
    assert canon(0) == "0"
    assert canon(-5) == "-5"


def test_cost_usd_float_round_trips_bit_exactly():
    # This exact float is the cost_usd of entry 0 in the TS demo fixture; it must
    # canonicalize identically or the entry hash diverges.
    assert canon(0.0019500000000000001) == "0.0019500000000000001"


def test_non_finite_numbers_are_rejected():
    for bad in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(CanonicalizationError):
            jcs_bytes(bad)


# --- UTF-16 code-unit key ordering -------------------------------------------

def test_utf16_key_ordering_vector():
    euro, cr, c1, odia = chr(0x20AC), chr(0x000D), chr(0x0080), chr(0x00F6)
    obj = {euro: "Euro", cr: "CR", "1": "One", c1: "Ctrl", odia: "ODia"}
    # Expected order by code unit: \r (0x0D) < '1' (0x31) < U+0080 < U+00F6 < U+20AC.
    expected = (
        "{"
        '"\\r":"CR",'
        '"1":"One",'
        f'"{c1}":"Ctrl",'
        f'"{odia}":"ODia",'
        f'"{euro}":"Euro"'
        "}"
    )
    assert canon(obj) == expected


def test_nested_objects_recursively_sorted():
    assert canon({"b": {"d": 1, "c": 2}, "a": [3, {"f": 4, "e": 5}]}) == (
        '{"a":[3,{"e":5,"f":4}],"b":{"c":2,"d":1}}'
    )


def test_ordering_insensitive_to_insertion_order():
    assert canon({"z": 1, "a": 2, "m": 3}) == canon({"a": 2, "m": 3, "z": 1})
    assert canon({"z": 1, "a": 2, "m": 3}) == '{"a":2,"m":3,"z":1}'


# --- String escaping ----------------------------------------------------------

def test_control_character_escaping():
    text = chr(0x0000) + "\b\t\n\f\r" + '"' + "\\" + "/"
    assert canon(text) == '"\\u0000\\b\\t\\n\\f\\r\\"\\\\/"'


def test_other_c0_control_uses_lowercase_u_escape():
    assert canon(chr(0x001F)) == '"\\u001f"'


def test_valid_surrogate_pair_emitted_literally():
    emoji = chr(0x1F600)  # a single well-formed code point
    assert jcs_bytes(emoji) == ('"' + emoji + '"').encode("utf-8")


# --- E7: lone surrogate rejection (F8) ---------------------------------------

@pytest.mark.parametrize("cp", [0xD800, 0xD801, 0xDC00])
def test_lone_surrogate_rejected(cp):
    with pytest.raises(CanonicalizationError):
        jcs_bytes(chr(cp))


def test_lone_surrogate_rejected_embedded_and_as_key_and_in_array():
    # A lone surrogate in a string VALUE raises the library's CanonicalizationError.
    with pytest.raises(CanonicalizationError):
        jcs_bytes("safe" + chr(0xD800) + "text")
    with pytest.raises(CanonicalizationError):
        jcs_bytes(["ok", chr(0xD83D)])
    # A lone surrogate in a KEY is also rejected (never silently mangled), but the
    # rfc8785 library surfaces it as a UnicodeEncodeError from the utf-16be key
    # sort rather than CanonicalizationError. The contract that matters for F8 is
    # "rejected, not mangled"; the differing exception *type* between the value
    # path and the key path is a portability wrinkle (reported to the director).
    with pytest.raises((CanonicalizationError, UnicodeEncodeError)):
        jcs_bytes({"k" + chr(0xDC00): 1})


def test_sha256_jcs_is_hash_of_canonical_bytes():
    obj = {"b": 2, "a": 1}
    assert sha256_jcs(obj) == sha256_hex(jcs_bytes(obj))
