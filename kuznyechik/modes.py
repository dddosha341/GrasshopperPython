"""
Режимы работы блочного шифра по ГОСТ 34.13-2015.
ECB, CBC, OFB, CFB, CTR. Дополнение по процедуре 1.
Параллельные ECB через ProcessPoolExecutor для больших объёмов.
"""

from concurrent.futures import ProcessPoolExecutor
from typing import Callable, Optional
import os

from .kuznyechik import Kuznyechik, BLOCK_SIZE

# Размер чанка для параллельного ECB (должен быть кратен 16)
DEFAULT_CHUNK_SIZE = 1 << 20  # 1 МБ
PARALLEL_THRESHOLD = 256 * 1024  # 256 КБ — порог для включения параллелизма

BlockCipher = Callable[[bytearray], None]


def pad_procedure1(data: bytes) -> bytearray:
    """
    Дополнение по процедуре 1: P* = P || 1 || 0^{r-1}, r = 16 - (|P| mod 16).
    Если |P| кратно 16, добавляем блок 1||0^15.
    """
    n = len(data)
    r = BLOCK_SIZE - (n % BLOCK_SIZE)
    if r == 0:
        r = BLOCK_SIZE
    result = bytearray(data)
    result.append(0x80)  # 1 в битовом представлении = 0x80 в первом байте
    result.extend([0] * (r - 1))
    return result


def unpad_procedure1(data: bytearray) -> bytearray:
    """Удаление дополнения процедуры 1: ищем 1 и обнуляем хвост до неё."""
    for i in range(len(data) - 1, -1, -1):
        if data[i] == 0x80:
            return data[:i]
        if data[i] != 0:
            break
    return data


def _block_encrypt(cipher: Kuznyechik, block: bytearray) -> None:
    cipher.encrypt_block(block)


def _block_decrypt(cipher: Kuznyechik, block: bytearray) -> None:
    cipher.decrypt_block(block)


def ecb_encrypt(cipher: Kuznyechik, data: bytes, pad: bool = True) -> bytearray:
    if pad:
        data = pad_procedure1(data)
    else:
        data = bytes(data)
    result = bytearray(len(data))
    for i in range(0, len(data), BLOCK_SIZE):
        block = bytearray(data[i : i + BLOCK_SIZE])
        _block_encrypt(cipher, block)
        result[i : i + BLOCK_SIZE] = block
    return result


def ecb_decrypt(cipher: Kuznyechik, data: bytes, unpad: bool = True) -> bytearray:
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("Data length must be multiple of block size")
    result = bytearray(len(data))
    for i in range(0, len(data), BLOCK_SIZE):
        block = bytearray(data[i : i + BLOCK_SIZE])
        _block_decrypt(cipher, block)
        result[i : i + BLOCK_SIZE] = block
    if unpad:
        result = unpad_procedure1(result)
    return result


def _ecb_chunk_worker(args: tuple) -> bytes:
    """
    Воркер для параллельного ECB: (key, chunk, encrypt).
    Верхнеуровневая функция для pickle при multiprocessing.
    """
    key, chunk, encrypt = args
    cipher = Kuznyechik(key, use_mi_tables=True)
    result = bytearray(chunk)
    for i in range(0, len(result), BLOCK_SIZE):
        block = result[i : i + BLOCK_SIZE]
        if encrypt:
            cipher.encrypt_block(block)
        else:
            cipher.decrypt_block(block)
        result[i : i + BLOCK_SIZE] = block
    return bytes(result)


def ecb_encrypt_parallel(
    key: bytes,
    data: bytes,
    pad: bool = True,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    max_workers: Optional[int] = None,
) -> bytearray:
    """Шифрование ECB с разбиением на чанки по процессам (без pad/unpad внутри чанков)."""
    if pad:
        data = pad_procedure1(data)
    else:
        data = bytearray(data)
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("Data length must be multiple of block size after pad")
    n_workers = max_workers or os.cpu_count() or 4
    chunk_size = (chunk_size // BLOCK_SIZE) * BLOCK_SIZE
    if chunk_size < BLOCK_SIZE:
        chunk_size = BLOCK_SIZE
    if len(data) < PARALLEL_THRESHOLD:
        cipher = Kuznyechik(key, use_mi_tables=True)
        return ecb_encrypt(cipher, bytes(data), pad=False)
    chunks = []
    for start in range(0, len(data), chunk_size):
        chunks.append(bytes(data[start : start + chunk_size]))
    n_workers = min(n_workers, len(chunks))
    tasks = [(key, c, True) for c in chunks]
    with ProcessPoolExecutor(max_workers=n_workers) as executor:
        results = list(executor.map(_ecb_chunk_worker, tasks))
    return bytearray(b"".join(results))


def ecb_decrypt_parallel(
    key: bytes,
    data: bytes,
    unpad: bool = True,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    max_workers: Optional[int] = None,
) -> bytearray:
    """Дешифрование ECB с разбиением на чанки по процессам."""
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("Data length must be multiple of block size")
    n_workers = max_workers or os.cpu_count() or 4
    chunk_size = (chunk_size // BLOCK_SIZE) * BLOCK_SIZE
    if chunk_size < BLOCK_SIZE:
        chunk_size = BLOCK_SIZE
    if len(data) < PARALLEL_THRESHOLD:
        cipher = Kuznyechik(key, use_mi_tables=True)
        return ecb_decrypt(cipher, data, unpad=unpad)
    chunks = []
    for start in range(0, len(data), chunk_size):
        chunks.append(data[start : start + chunk_size])
    n_workers = min(n_workers, len(chunks))
    tasks = [(key, c, False) for c in chunks]
    with ProcessPoolExecutor(max_workers=n_workers) as executor:
        results = list(executor.map(_ecb_chunk_worker, tasks))
    result = bytearray(b"".join(results))
    if unpad:
        result = unpad_procedure1(result)
    return result


def _inc_counter(block: bytearray) -> None:
    """Инкремент 128-битного счётчика (младший байт в block[15])."""
    carry = 1
    for i in range(15, -1, -1):
        carry += block[i]
        block[i] = carry & 0xFF
        carry >>= 8


def _msb_n(data: bytearray, n: int) -> bytearray:
    return bytearray(data[:n])


def cbc_encrypt(
    cipher: Kuznyechik, data: bytes, iv: bytes, pad: bool = True
) -> bytearray:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be 16 bytes")
    if pad:
        data = pad_procedure1(data)
    else:
        data = bytes(data)
    result = bytearray(len(data))
    prev = bytearray(iv)
    for i in range(0, len(data), BLOCK_SIZE):
        block = bytearray(data[i : i + BLOCK_SIZE])
        for j in range(BLOCK_SIZE):
            block[j] ^= prev[j]
        _block_encrypt(cipher, block)
        result[i : i + BLOCK_SIZE] = block
        prev = block
    return result


def cbc_decrypt(
    cipher: Kuznyechik, data: bytes, iv: bytes, unpad: bool = True
) -> bytearray:
    if len(iv) != BLOCK_SIZE or len(data) % BLOCK_SIZE != 0:
        raise ValueError("IV 16 bytes, data length multiple of 16")
    result = bytearray(len(data))
    prev = bytearray(iv)
    for i in range(0, len(data), BLOCK_SIZE):
        block = bytearray(data[i : i + BLOCK_SIZE])
        _block_decrypt(cipher, block)
        for j in range(BLOCK_SIZE):
            block[j] ^= prev[j]
        result[i : i + BLOCK_SIZE] = block
        prev = bytearray(data[i : i + BLOCK_SIZE])
    if unpad:
        result = unpad_procedure1(result)
    return result


def ofb_encrypt(
    cipher: Kuznyechik, data: bytes, iv: bytes, pad: bool = True
) -> bytearray:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be 16 bytes")
    if pad:
        data = pad_procedure1(data)
    else:
        data = bytes(data)
    result = bytearray(len(data))
    state = bytearray(iv)
    for i in range(0, len(data), BLOCK_SIZE):
        _block_encrypt(cipher, state)
        chunk = min(BLOCK_SIZE, len(data) - i)
        for j in range(chunk):
            result[i + j] = data[i + j] ^ state[j]
    return result


def ofb_decrypt(
    cipher: Kuznyechik, data: bytes, iv: bytes, unpad: bool = True
) -> bytearray:
    out = ofb_encrypt(cipher, data, iv, pad=False)
    if unpad:
        return unpad_procedure1(out)
    return out


def cfb_encrypt(
    cipher: Kuznyechik, data: bytes, iv: bytes, pad: bool = True
) -> bytearray:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be 16 bytes")
    if pad:
        data = pad_procedure1(data)
    else:
        data = bytes(data)
    result = bytearray(len(data))
    state = bytearray(iv)
    for i in range(0, len(data), BLOCK_SIZE):
        _block_encrypt(cipher, state)
        chunk = min(BLOCK_SIZE, len(data) - i)
        for j in range(chunk):
            result[i + j] = data[i + j] ^ state[j]
        # CFB: next state = ciphertext block (or partial)
        for j in range(BLOCK_SIZE):
            if j < chunk:
                state[j] = result[i + j]
            else:
                state[j] = 0
    return result


def cfb_decrypt(
    cipher: Kuznyechik, data: bytes, iv: bytes, unpad: bool = True
) -> bytearray:
    if len(iv) != BLOCK_SIZE or len(data) % BLOCK_SIZE != 0:
        if len(data) % BLOCK_SIZE != 0:
            raise ValueError("Data length must be multiple of 16 for CFB decrypt")
    result = bytearray(len(data))
    state = bytearray(iv)
    for i in range(0, len(data), BLOCK_SIZE):
        _block_encrypt(cipher, state)
        chunk = min(BLOCK_SIZE, len(data) - i)
        for j in range(chunk):
            result[i + j] = data[i + j] ^ state[j]
        for j in range(BLOCK_SIZE):
            state[j] = data[i + j] if j < chunk else 0
    if unpad:
        result = unpad_procedure1(result)
    return result


def ctr_encrypt(
    cipher: Kuznyechik, data: bytes, iv: Optional[bytes] = None, pad: bool = False
) -> tuple:
    """
    CTR: гамма O_i = E(SV + i-1). SV = IV (16 байт). Без дополнения по умолчанию.
    Возвращает (ciphertext, iv_used).
    """
    if iv is None:
        iv = os.urandom(BLOCK_SIZE)
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be 16 bytes")
    if pad:
        data = pad_procedure1(data)
    else:
        data = bytes(data)
    result = bytearray(len(data))
    counter = bytearray(iv)
    for i in range(0, len(data), BLOCK_SIZE):
        block = bytearray(counter)
        _block_encrypt(cipher, block)
        chunk = min(BLOCK_SIZE, len(data) - i)
        for j in range(chunk):
            result[i + j] = data[i + j] ^ block[j]
        _inc_counter(counter)
    return (result, bytes(iv))


def ctr_decrypt(
    cipher: Kuznyechik, data: bytes, iv: bytes, unpad: bool = False
) -> bytearray:
    result = bytearray(len(data))
    counter = bytearray(iv)
    for i in range(0, len(data), BLOCK_SIZE):
        block = bytearray(counter)
        _block_encrypt(cipher, block)
        chunk = min(BLOCK_SIZE, len(data) - i)
        for j in range(chunk):
            result[i + j] = data[i + j] ^ block[j]
        _inc_counter(counter)
    if unpad:
        result = unpad_procedure1(result)
    return result
