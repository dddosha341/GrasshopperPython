"""
Блочный шифр «Кузнечик» (ГОСТ 34.12-2015).
Ключ 256 бит, блок 128 бит, 10 раундов.
"""

from typing import List, Callable

from . import tables
from . import l_transform

BLOCK_SIZE: int = 16
KEY_SIZE: int = 32

S = tables.SBOX
S_INV = tables.SBOX_INV


def _xor_block(a: bytearray, b: bytes) -> None:
    for i in range(16):
        a[i] ^= b[i]


def _s_apply(block: bytearray, s_table: tuple) -> None:
    for i in range(16):
        block[i] = s_table[block[i]]


# Константы C_i = L(Vec_128(i)) для i=1..32. Vec_128(i) — 128-битное представление i (младший байт первый).
def _build_constants() -> List[bytes]:
    """C_i = L(Vec_128(i)). Vec_128(i) — 128 бит, младший байт в block[15]."""
    constants: List[bytes] = []
    for i in range(1, 33):
        v = bytearray(16)
        v[15] = i & 0xFF
        if i >= 256:
            v[14] = (i >> 8) & 0xFF
        l_transform.l_transform_reference(v)
        # Результат L уже в порядке block[0]=старший
        constants.append(bytes(v))
    return constants


_ROUND_CONSTANTS: List[bytes] = _build_constants()


def key_schedule(key: bytes) -> List[bytes]:
    """Разложение ключа в 10 раундовых ключей K_1..K_10."""
    if len(key) != KEY_SIZE:
        raise ValueError("Key must be 32 bytes")
    k1 = bytearray(key[:16])
    k2 = bytearray(key[16:])
    round_keys: List[bytes] = [bytes(k1), bytes(k2)]
    for r in range(4):
        for j in range(8):
            c = _ROUND_CONSTANTS[r * 8 + j]
            k1_old = bytes(k1)
            t = bytearray(k1)
            _xor_block(t, c)
            _s_apply(t, S)
            l_transform.l_transform_reference(t)
            _xor_block(t, k2)
            k2[:] = k1_old
            k1[:] = t
        round_keys.append(bytes(k1))
        round_keys.append(bytes(k2))
    return round_keys  # [K1, K2, K3, K4, ..., K10] — 10 ключей


def _encrypt_block_reference(block: bytearray, round_keys: List[bytes]) -> None:
    """Шифрование блока: 9 раундов LSX[K_i], затем X[K_10]."""
    for r in range(9):
        _xor_block(block, round_keys[r])
        _s_apply(block, S)
        l_transform.l_transform_reference(block)
    _xor_block(block, round_keys[9])


def _decrypt_block_reference(block: bytearray, round_keys: List[bytes]) -> None:
    """Расшифрование: D = X[K_10] L^(-1) S^(-1) X[K_9] ... X[K_1]. (L S)^{-1} = L^{-1} затем S^{-1}."""
    for r in range(9):
        _xor_block(block, round_keys[9 - r])
        l_transform.l_inverse_transform_reference(block)
        _s_apply(block, S_INV)
    _xor_block(block, round_keys[0])


def _encrypt_block_matrix(block: bytearray, round_keys: List[bytes]) -> None:
    for r in range(9):
        _xor_block(block, round_keys[r])
        _s_apply(block, S)
        l_transform.l_transform_matrix(block)
    _xor_block(block, round_keys[9])


def _decrypt_block_matrix(block: bytearray, round_keys: List[bytes]) -> None:
    for r in range(9):
        _xor_block(block, round_keys[9 - r])
        l_transform.l_inverse_transform_matrix(block)
        _s_apply(block, S_INV)
    _xor_block(block, round_keys[0])


def _encrypt_block_mi(block: bytearray, round_keys: List[bytes]) -> None:
    for r in range(9):
        _xor_block(block, round_keys[r])
        _s_apply(block, S)
        l_transform.l_transform_mi_tables(block)
    _xor_block(block, round_keys[9])


def _decrypt_block_mi(block: bytearray, round_keys: List[bytes]) -> None:
    for r in range(9):
        _xor_block(block, round_keys[9 - r])
        l_transform.l_inverse_transform_mi_tables(block)
        _s_apply(block, S_INV)
    _xor_block(block, round_keys[0])


class Kuznyechik:
    """Шифр «Кузнечик» с выбором реализации L (reference / matrix / mi_tables)."""

    def __init__(self, key: bytes, use_matrix_l: bool = False, use_mi_tables: bool = False):
        self._round_keys = key_schedule(key)
        if use_mi_tables:
            self._encrypt = _encrypt_block_mi
            self._decrypt = _decrypt_block_mi
        elif use_matrix_l:
            self._encrypt = _encrypt_block_matrix
            self._decrypt = _decrypt_block_matrix
        else:
            self._encrypt = _encrypt_block_reference
            self._decrypt = _decrypt_block_reference

    def encrypt_block(self, block: bytearray) -> None:
        self._encrypt(block, self._round_keys)

    def decrypt_block(self, block: bytearray) -> None:
        self._decrypt(block, self._round_keys)


