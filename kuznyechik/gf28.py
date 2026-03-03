"""
Арифметика конечного поля GF(2^8) для шифра «Кузнечик» (ГОСТ 34.12-2015).
Модуль: x^8 + x^7 + x^6 + x + 1 = 0x1C3.
Чистая реализация без сторонних библиотек.
"""

from typing import List

# Неприводимый полином для поля Кузнечика: x^8 + x^7 + x^6 + x + 1
GF28_MOD: int = 0x1C3  # 451


def mul(a: int, b: int, mod: int = GF28_MOD) -> int:
    """
    Умножение в конечном поле GF(2^8).
    a, b — элементы поля (0..255), mod — неприводимый полином.
    Возвращает (a * b) mod mod в GF(2).
    """
    a = a & 0xFF
    b = b & 0xFF
    if a == 0 or b == 0:
        return 0
    p: int = 0
    while b:
        if b & 1:
            p ^= a
        a <<= 1
        if a & 0x100:
            a ^= mod
        a &= 0xFF
        b >>= 1
    return p


def _build_mul_table(mod: int) -> List[List[int]]:
    """Строит таблицу умножения gf_mul[i][j] для i, j in 0..255."""
    table: List[List[int]] = [[0] * 256 for _ in range(256)]
    for i in range(256):
        for j in range(256):
            table[i][j] = mul(i, j, mod)
    return table


# Предвычисленная таблица умножения в GF(2^8) с модулем ГОСТ
_GF_MUL_TABLE: List[List[int]] = _build_mul_table(GF28_MOD)


def gf_mul_table(i: int, j: int) -> int:
    """Умножение в GF(2^8) по таблице. i, j in 0..255."""
    return _GF_MUL_TABLE[i & 0xFF][j & 0xFF]


def get_mul_table() -> List[List[int]]:
    """Возвращает таблицу умножения (для использования в L и таблицах)."""
    return _GF_MUL_TABLE
