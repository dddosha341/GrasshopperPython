"""Тесты режимов шифрования."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from kuznyechik.kuznyechik import Kuznyechik
from kuznyechik.modes import (
    pad_procedure1,
    unpad_procedure1,
    ecb_encrypt,
    ecb_decrypt,
    cbc_encrypt,
    cbc_decrypt,
    ofb_encrypt,
    ofb_decrypt,
    cfb_encrypt,
    cfb_decrypt,
    ctr_encrypt,
    ctr_decrypt,
)

KEY = bytes.fromhex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
IV = bytes.fromhex("1122334455667700ffeeddccbbaa9988")


def test_pad_unpad():
    for length in [0, 1, 15, 16, 17, 32]:
        data = b"x" * length
        padded = pad_procedure1(data)
        assert len(padded) % 16 == 0
        unpadded = unpad_procedure1(bytearray(padded))
        assert bytes(unpadded) == data


def test_ecb_roundtrip():
    plain = b"Hello, Kuznyechik!"
    cipher = Kuznyechik(KEY)
    ct = ecb_encrypt(cipher, plain, pad=True)
    pt = ecb_decrypt(cipher, bytes(ct), unpad=True)
    assert pt == plain


def test_cbc_roundtrip():
    plain = b"Secret message for CBC mode."
    cipher = Kuznyechik(KEY)
    ct = cbc_encrypt(cipher, plain, IV, pad=True)
    pt = cbc_decrypt(cipher, bytes(ct), IV, unpad=True)
    assert pt == plain


def test_ofb_roundtrip():
    plain = b"OFB test data"
    cipher = Kuznyechik(KEY)
    ct = ofb_encrypt(cipher, plain, IV, pad=True)
    pt = ofb_decrypt(cipher, bytes(ct), IV, unpad=True)
    assert pt == plain


def test_cfb_roundtrip():
    plain = b"CFB test"
    cipher = Kuznyechik(KEY)
    ct = cfb_encrypt(cipher, plain, IV, pad=True)
    pt = cfb_decrypt(cipher, bytes(ct), IV, unpad=True)
    assert pt == plain


def test_ctr_roundtrip():
    plain = b"CTR mode test"
    cipher = Kuznyechik(KEY)
    ct, iv = ctr_encrypt(cipher, plain, pad=False)
    pt = ctr_decrypt(cipher, bytes(ct), iv, unpad=False)
    assert pt == plain
