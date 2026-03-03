"""Тесты для L и L^(-1), матрицы M."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from kuznyechik import l_transform


def test_l_inverse_roundtrip():
    block = bytearray(range(16))
    original = bytearray(block)
    l_transform.l_transform_reference(block)
    l_transform.l_inverse_transform_reference(block)
    assert block == original


def test_matrix_same_as_reference():
    block = bytearray(range(16))
    ref = bytearray(block)
    mat = bytearray(block)
    l_transform.l_transform_reference(ref)
    l_transform.l_transform_matrix(mat)
    assert ref == mat


def test_matrix_inverse_roundtrip():
    block = bytearray([7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6])
    original = bytearray(block)
    l_transform.l_transform_matrix(block)
    l_transform.l_inverse_transform_matrix(block)
    assert block == original


def test_r_example_rfc():
    v = bytearray.fromhex("00000000000000000000000000000100")
    l_transform.r_transform(v)
    assert v.hex() == "94000000000000000000000000000001"
