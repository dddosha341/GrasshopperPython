"""Тесты для GF(2^8)."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from kuznyechik.gf28 import mul, GF28_MOD, gf_mul_table


def test_mul_zero():
    assert mul(0, 100, GF28_MOD) == 0
    assert mul(100, 0, GF28_MOD) == 0


def test_mul_one():
    for a in [1, 255, 42]:
        assert mul(a, 1, GF28_MOD) == a
        assert mul(1, a, GF28_MOD) == a


def test_mul_consistency():
    for a in range(256):
        for b in range(256):
            assert mul(a, b, GF28_MOD) == gf_mul_table(a, b)


def test_mul_inverse():
    # В GF(2^8) для a != 0 есть a^(-1) такой что a * a^(-1) = 1
    for a in range(1, 256):
        inv = 1
        for _ in range(254):
            inv = gf_mul_table(inv, a)
        assert gf_mul_table(a, inv) == 1
