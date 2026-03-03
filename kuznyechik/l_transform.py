"""
Линейное преобразование L для «Кузнечик» (ГОСТ 34.12-2015).
R — один шаг, L = R^16. Матричное представление M, L(x)=M·x, таблицы M_i.
"""

from typing import List, Tuple

from . import tables

BLOCK_SIZE: int = 16
C = tables.C_VECTOR
_gf_mul = tables.gf_mul_table


def _l_byte(a: bytearray) -> int:
    """l(a_15,...,a_0). block[0]=a_15 (старший), block[15]=a_0 (младший)."""
    t = 0
    for i in range(16):
        t ^= _gf_mul(C[i], a[i])
    return t & 0xFF


def r_transform(block: bytearray) -> None:
    """
    R-преобразование по месту. RFC: R(a_15||...||a_0) = l||a_15||...||a_1.
    block[0]=a_15 (старший), block[15]=a_0 (младший).
    """
    l_val = _l_byte(block)
    # new[0]=l, new[1]=block[0]=a_15, ..., new[15]=block[14]=a_1
    for i in range(15, 0, -1):
        block[i] = block[i - 1]
    block[0] = l_val


def l_transform_reference(block: bytearray) -> None:
    """L = R^16, эталонная реализация (16 раз R)."""
    for _ in range(16):
        r_transform(block)


def _r_inverse_byte(a: bytearray) -> int:
    """Линейная часть обратного R: l(a_14, a_13, ..., a_0, a_15)."""
    # R^(-1)(a_15..a_0) = (a_14, a_13, ..., a_0, l(a_14,...,a_0,a_15))
    # т.е. аргументы l сдвинуты: первый аргумент a_14, последний a_15
    t = 0
    for i in range(16):
        # l принимает (x_15,...,x_0), у нас x_15=a_14, x_14=a_13, ..., x_1=a_0, x_0=a_15
        # l = C[0]*x_15 + C[1]*x_14 + ... + C[15]*x_0
        #   = C[0]*a_14 + C[1]*a_13 + ... + C[14]*a_0 + C[15]*a_15
        idx = (15 - i + 1) % 16  # a_14 at i=0 -> block[14], a_15 at i=15 -> block[15]
        t ^= _gf_mul(C[i], block[(14 - i + 16) % 16])
    return t & 0xFF


def r_inverse_transform(block: bytearray) -> None:
    """
    R^(-1): input = (l, a_15, ..., a_1). Output = (a_15, ..., a_0) where a_0 = l xor C[0]*a_15 xor ... xor C[14]*a_1.
    """
    new_block = bytearray(16)
    for i in range(15):
        new_block[i] = block[i + 1]
    # a_0 = l xor sum C[i]*a_{15-i} for i=0..14; a_15=new[0], ..., a_1=new[14]
    a0 = block[0]
    for i in range(15):
        a0 ^= _gf_mul(C[i], new_block[i])
    new_block[15] = a0 & 0xFF
    block[:] = new_block


def l_inverse_transform_reference(block: bytearray) -> None:
    """L^(-1) = (R^(-1))^16."""
    for _ in range(16):
        r_inverse_transform(block)


# --- Матричное представление M, L(x)=M·x ---

def _compute_matrix_m() -> List[List[int]]:
    """Строит матрицу 16x16 M: L(e_j) = j-й столбец M (индексы 0..15)."""
    M: List[List[int]] = [[0] * 16 for _ in range(16)]
    for j in range(16):
        ej = bytearray(16)
        ej[j] = 1
        l_transform_reference(ej)
        for i in range(16):
            M[i][j] = ej[i]
    return M


def _matrix_vector_mul(M: List[List[int]], x: bytearray) -> bytearray:
    """(M·x)_i = sum_j gf_mul(M[i][j], x[j])."""
    out = bytearray(16)
    for i in range(16):
        s = 0
        for j in range(16):
            s ^= _gf_mul(M[i][j], x[j])
        out[i] = s & 0xFF
    return out


def _gauss_jordan_inverse(M: List[List[int]]) -> List[List[int]]:
    """Обратная матрица к M над GF(2^8). [M|I] -> [I|M^(-1)]."""
    n = 16
    A = [list(M[i]) + [1 if i == j else 0 for j in range(n)] for i in range(n)]
    for col in range(n):
        pivot = -1
        for row in range(col, n):
            if A[row][col] != 0:
                pivot = row
                break
        if pivot == -1:
            raise ValueError("Matrix is singular")
        A[col], A[pivot] = A[pivot], A[col]
        inv = 1
        # В GF(2^8) обратный элемент: a^(-1) = a^(254)
        c = A[col][col]
        if c != 1:
            for _ in range(254):
                inv = _gf_mul(inv, c)
            for j in range(2 * n):
                A[col][j] = _gf_mul(A[col][j], inv)
        for row in range(n):
            if row != col and A[row][col] != 0:
                f = A[row][col]
                for j in range(2 * n):
                    A[row][j] ^= _gf_mul(f, A[col][j])
    return [A[i][n:] for i in range(n)]


# Предвычисленные матрицы
_MATRIX_M: List[List[int]] = _compute_matrix_m()
_MATRIX_M_INV: List[List[int]] = _gauss_jordan_inverse(_MATRIX_M)


def get_matrix_m() -> List[List[int]]:
    return [row[:] for row in _MATRIX_M]


def get_matrix_m_inv() -> List[List[int]]:
    return [row[:] for row in _MATRIX_M_INV]


def l_transform_matrix(block: bytearray) -> None:
    """L(x) = M·x, по месту."""
    out = _matrix_vector_mul(_MATRIX_M, block)
    block[:] = out


def l_inverse_transform_matrix(block: bytearray) -> None:
    """L^(-1)(x) = M^(-1)·x."""
    out = _matrix_vector_mul(_MATRIX_M_INV, block)
    block[:] = out


# --- Таблицы M_i: для каждого i таблица T_i[b] = вклад байта b в позиции i в L(x) ---

def _build_mi_tables() -> Tuple[List[bytearray], List[bytearray]]:
    """
    M_i[b] — 16-байтовый вектор вклада x_i=b в L(x).
    L(x) = M_0[x_0] xor M_1[x_1] xor ... xor M_15[x_15].
    Аналогично для L^(-1).
    """
    L_tables: List[bytearray] = [bytearray(16) for _ in range(256 * 16)]
    # L_tables[i*256 + b] = вклад байта b в позиции i (16 байт)
    for pos in range(16):
        for b in range(256):
            x = bytearray(16)
            x[pos] = b
            l_transform_reference(x)
            for j in range(16):
                L_tables[pos * 256 + b][j] = x[j]
    # Оптимизированный формат: 16 таблиц по 256 строк по 16 байт
    L_Mi: List[bytearray] = []  # L_Mi[i][b*16:(b+1)*16] = 16 bytes for position i, byte b
    for pos in range(16):
        tab = bytearray(256 * 16)
        for b in range(256):
            for j in range(16):
                tab[b * 16 + j] = L_tables[pos * 256 + b][j]
        L_Mi.append(tab)

    # L^(-1) tables
    Linv_tables: List[bytearray] = [bytearray(16) for _ in range(256 * 16)]
    for pos in range(16):
        for b in range(256):
            x = bytearray(16)
            x[pos] = b
            l_inverse_transform_reference(x)
            for j in range(16):
                Linv_tables[pos * 256 + b][j] = x[j]
    Linv_Mi: List[bytearray] = []
    for pos in range(16):
        tab = bytearray(256 * 16)
        for b in range(256):
            for j in range(16):
                tab[b * 16 + j] = Linv_tables[pos * 256 + b][j]
        Linv_Mi.append(tab)

    return (L_Mi, Linv_Mi)


_L_MI_TABLES, _L_INV_MI_TABLES = _build_mi_tables()


def l_transform_mi_tables(block: bytearray) -> None:
    """L(x) через таблицы M_i: результат = xor по i от M_i[block[i]]."""
    out = bytearray(16)
    for i in range(16):
        b = block[i]
        base = i * 256 + b
        for j in range(16):
            out[j] ^= _L_MI_TABLES[i][b * 16 + j]
    block[:] = out


def l_inverse_transform_mi_tables(block: bytearray) -> None:
    """L^(-1)(x) через таблицы."""
    out = bytearray(16)
    for i in range(16):
        b = block[i]
        for j in range(16):
            out[j] ^= _L_INV_MI_TABLES[i][b * 16 + j]
    block[:] = out
