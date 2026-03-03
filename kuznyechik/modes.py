"""
Режимы работы блочного шифра по ГОСТ 34.13-2015.
ECB, CBC, OFB, CFB, CTR. Дополнение по процедуре 1.
"""

from typing import Callable, Optional
import os

from .kuznyechik import Kuznyechik, BLOCK_SIZE

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
