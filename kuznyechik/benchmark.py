"""
Сравнение производительности эталонной и матричной реализации L
на больших данных для режимов ECB, CBC, OFB, CFB, CTR.
"""

import time
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kuznyechik.kuznyechik import Kuznyechik
from kuznyechik.modes import (
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

# Размер тестовых данных (МБ). Для полного бенчмарка можно задать 50+ (видео).
# Для быстрой проверки: 0.01 МБ. Для сравнения на больших данных: 10–50 МБ.
DATA_SIZE_MB = float(os.environ.get("KUZNECHIK_BENCHMARK_MB", "0.01"))
BLOCK_SIZE = 16
KEY = os.urandom(32)
IV = os.urandom(16)


def run_benchmark(data: bytes, cipher_ref: Kuznyechik, cipher_mat: Kuznyechik):
    """Замер encrypt/decrypt для эталонной и матричной реализации."""
    results = {}
    # ECB
    t0 = time.perf_counter()
    ct = ecb_encrypt(cipher_ref, data, pad=True)
    t1 = time.perf_counter()
    ecb_decrypt(cipher_ref, ct, unpad=True)
    t2 = time.perf_counter()
    results["ECB_ref_enc"] = t1 - t0
    results["ECB_ref_dec"] = t2 - t1
    t0 = time.perf_counter()
    ct = ecb_encrypt(cipher_mat, data, pad=True)
    t1 = time.perf_counter()
    ecb_decrypt(cipher_mat, ct, unpad=True)
    t2 = time.perf_counter()
    results["ECB_mat_enc"] = t1 - t0
    results["ECB_mat_dec"] = t2 - t1
    # CBC
    t0 = time.perf_counter()
    ct = cbc_encrypt(cipher_ref, data, IV, pad=True)
    t1 = time.perf_counter()
    cbc_decrypt(cipher_ref, ct, IV, unpad=True)
    t2 = time.perf_counter()
    results["CBC_ref_enc"] = t1 - t0
    results["CBC_ref_dec"] = t2 - t1
    t0 = time.perf_counter()
    ct = cbc_encrypt(cipher_mat, data, IV, pad=True)
    t1 = time.perf_counter()
    cbc_decrypt(cipher_mat, ct, IV, unpad=True)
    t2 = time.perf_counter()
    results["CBC_mat_enc"] = t1 - t0
    results["CBC_mat_dec"] = t2 - t1
    # OFB
    t0 = time.perf_counter()
    ct = ofb_encrypt(cipher_ref, data, IV, pad=True)
    t1 = time.perf_counter()
    ofb_decrypt(cipher_ref, ct, IV, unpad=True)
    t2 = time.perf_counter()
    results["OFB_ref_enc"] = t1 - t0
    results["OFB_ref_dec"] = t2 - t1
    t0 = time.perf_counter()
    ct = ofb_encrypt(cipher_mat, data, IV, pad=True)
    t1 = time.perf_counter()
    ofb_decrypt(cipher_mat, ct, IV, unpad=True)
    t2 = time.perf_counter()
    results["OFB_mat_enc"] = t1 - t0
    results["OFB_mat_dec"] = t2 - t1
    # CFB
    t0 = time.perf_counter()
    ct = cfb_encrypt(cipher_ref, data, IV, pad=True)
    t1 = time.perf_counter()
    cfb_decrypt(cipher_ref, ct, IV, unpad=True)
    t2 = time.perf_counter()
    results["CFB_ref_enc"] = t1 - t0
    results["CFB_ref_dec"] = t2 - t1
    t0 = time.perf_counter()
    ct = cfb_encrypt(cipher_mat, data, IV, pad=True)
    t1 = time.perf_counter()
    cfb_decrypt(cipher_mat, ct, IV, unpad=True)
    t2 = time.perf_counter()
    results["CFB_mat_enc"] = t1 - t0
    results["CFB_mat_dec"] = t2 - t1
    # CTR
    t0 = time.perf_counter()
    ct, _ = ctr_encrypt(cipher_ref, data, IV, pad=False)
    t1 = time.perf_counter()
    ctr_decrypt(cipher_ref, ct, IV, unpad=False)
    t2 = time.perf_counter()
    results["CTR_ref_enc"] = t1 - t0
    results["CTR_ref_dec"] = t2 - t1
    t0 = time.perf_counter()
    ct, _ = ctr_encrypt(cipher_mat, data, IV, pad=False)
    t1 = time.perf_counter()
    ctr_decrypt(cipher_mat, ct, IV, unpad=False)
    t2 = time.perf_counter()
    results["CTR_mat_enc"] = t1 - t0
    results["CTR_mat_dec"] = t2 - t1
    return results


def main():
    size_bytes = int(DATA_SIZE_MB * 1024 * 1024)
    if size_bytes < BLOCK_SIZE:
        size_bytes = BLOCK_SIZE * 100  # минимум 100 блоков
    data = os.urandom(size_bytes)
    cipher_ref = Kuznyechik(KEY, use_matrix_l=False)
    cipher_mat = Kuznyechik(KEY, use_matrix_l=True)
    print(f"Benchmark: {size_bytes / (1024*1024):.2f} MB data, block 16 bytes")
    print("-" * 70)
    results = run_benchmark(data, cipher_ref, cipher_mat)
    modes = ["ECB", "CBC", "OFB", "CFB", "CTR"]
    print(f"{'Mode':<6} {'Ref Enc (s)':<14} {'Ref Dec (s)':<14} {'Mat Enc (s)':<14} {'Mat Dec (s)':<14}")
    print("-" * 70)
    for mode in modes:
        ref_enc = results[f"{mode}_ref_enc"]
        ref_dec = results[f"{mode}_ref_dec"]
        mat_enc = results[f"{mode}_mat_enc"]
        mat_dec = results[f"{mode}_mat_dec"]
        print(f"{mode:<6} {ref_enc:<14.3f} {ref_dec:<14.3f} {mat_enc:<14.3f} {mat_dec:<14.3f}")
    print("-" * 70)
    total_ref = sum(results[f"{m}_ref_enc"] + results[f"{m}_ref_dec"] for m in modes)
    total_mat = sum(results[f"{m}_mat_enc"] + results[f"{m}_mat_dec"] for m in modes)
    print(f"Total reference: {total_ref:.3f} s, matrix: {total_mat:.3f} s")
    print(f"Speedup (matrix vs reference): {total_ref / total_mat:.2f}x")


if __name__ == "__main__":
    main()
