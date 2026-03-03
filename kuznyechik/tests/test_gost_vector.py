"""Тест по контрольному вектору ГОСТ 34.12-2015."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from kuznyechik.kuznyechik import Kuznyechik


def test_encrypt_decrypt():
    key_hex = "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"
    key = bytes.fromhex(key_hex)
    plain_hex = "1122334455667700ffeeddccbbaa9988"
    expected_cipher_hex = "7f679d90bebc24305a468d42b9d4edcd"
    plain = bytearray.fromhex(plain_hex)
    expected = bytearray.fromhex(expected_cipher_hex)
    cipher = Kuznyechik(key, use_matrix_l=False)
    block = bytearray(plain)
    cipher.encrypt_block(block)
    assert block == expected, f"Encrypt: got {block.hex()}, expected {expected_cipher_hex}"
    cipher.decrypt_block(block)
    assert block == plain, f"Decrypt: got {block.hex()}, expected {plain_hex}"
    print("GOST test vector (reference): OK")


def test_matrix_encrypt():
    key_hex = "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"
    key = bytes.fromhex(key_hex)
    plain_hex = "1122334455667700ffeeddccbbaa9988"
    expected_cipher_hex = "7f679d90bebc24305a468d42b9d4edcd"
    plain = bytearray.fromhex(plain_hex)
    expected = bytearray.fromhex(expected_cipher_hex)
    cipher = Kuznyechik(key, use_matrix_l=True)
    block = bytearray(plain)
    cipher.encrypt_block(block)
    assert block == expected, f"Matrix encrypt: got {block.hex()}"
    cipher.decrypt_block(block)
    assert block == plain
    print("GOST test vector (matrix): OK")


if __name__ == "__main__":
    test_encrypt_decrypt()
    test_matrix_encrypt()
