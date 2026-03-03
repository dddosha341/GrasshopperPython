"""
CLI: шифрование и расшифровка (режим ECB).
  encrypt <file> — шифрует файл, создаёт <file>.kuznyechik (key + data в base64).
  <path.kuznyechik> — расшифровывает файл.
Формат .kuznyechik: key: <hex>, data: <base64>
"""

import base64
import io
import os
import sys
import tempfile
import time

# Добавляем родительский каталог для импорта
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fpdf import FPDF
from fpdf.enums import XPos, YPos

from kuznyechik.kuznyechik import Kuznyechik
from kuznyechik.modes import (
    ecb_decrypt,
    ecb_encrypt,
    ecb_decrypt_parallel,
    ecb_encrypt_parallel,
    PARALLEL_THRESHOLD,
)


def run_encrypt(path_in: str) -> None:
    """Шифрует файл и сохраняет в <path_in>.kuznyechik (ключ + данные в base64)."""
    if not os.path.isfile(path_in):
        print(f"File not found: {path_in}", file=sys.stderr)
        sys.exit(1)
    with open(path_in, "rb") as f:
        plaintext = f.read()
    key = os.urandom(32)
    if len(plaintext) >= PARALLEL_THRESHOLD:
        ciphertext = ecb_encrypt_parallel(key, plaintext, pad=True)
    else:
        cipher = Kuznyechik(key, use_mi_tables=True)
        ciphertext = ecb_encrypt(cipher, plaintext, pad=True)
    path_out = path_in + ".kuznyechik"
    with open(path_out, "w", encoding="utf-8") as f:
        f.write(f"key: {key.hex()}\n")
        f.write(f"data: {base64.b64encode(ciphertext).decode()}\n")
    print(f"Зашифровано: {path_in} → {path_out}", file=sys.stderr)
    print("Ключ сохранён в .kuznyechik файле — храните его в секрете.", file=sys.stderr)


def parse_kuznyechik_file(path: str):
    """Читает файл с ключом (base16) и данными (base64). Возвращает (key, data)."""
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    key_hex = None
    data_b64 = None
    for line in content.splitlines():
        line = line.strip()
        if line.lower().startswith("key:"):
            key_hex = line[4:].strip().replace(" ", "")
        elif line.lower().startswith("data:"):
            data_b64 = line[5:].strip().replace(" ", "")
    if not key_hex or not data_b64:
        raise ValueError("File must contain 'key:' and 'data:' lines")
    key = bytes.fromhex(key_hex)
    data = base64.b64decode(data_b64)
    return (key, data)


def write_report_pdf(
    path_in: str,
    plaintext: bytes,
    size_bytes: int,
    time_sec: float,
    speed_mb_s: float,
) -> bytes:
    """Формирует PDF с отчётом и вложенным результатом дешифровки. Возвращает байты PDF."""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size=14)
    pdf.cell(0, 10, "Report: Kuznyechik decryption", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", size=11)
    pdf.cell(0, 8, f"Input file: {path_in}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(
        0, 8,
        f"Data size: {size_bytes} bytes ({size_bytes / (1024 * 1024):.2f} MB)",
        new_x=XPos.LMARGIN, new_y=YPos.NEXT,
    )
    pdf.cell(0, 8, f"Time: {time_sec:.3f} s", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 8, f"Speed: {speed_mb_s:.2f} MB/s", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(
        0, 8,
        f'Decryption result: attached as "decrypted.bin" ({size_bytes} bytes).',
        new_x=XPos.LMARGIN, new_y=YPos.NEXT,
    )
    # Превью: текст UTF-8 до 2 КБ или hex первых 64 байт
    try:
        text = plaintext.decode("utf-8")
        if len(text) > 2048:
            text = text[:2048] + "... (truncated)"
        preview = "Preview (UTF-8): " + text.replace("\r", " ").replace("\n", " ")
        if len(preview) > 200:
            preview = preview[:200] + "..."
    except UnicodeDecodeError:
        hex_preview = plaintext[:64].hex()
        preview = f"Preview (binary, first 64 bytes hex): {hex_preview}"
    pdf.cell(0, 8, preview, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    tmp_dir = tempfile.mkdtemp()
    tmp_path = os.path.join(tmp_dir, "decrypted.bin")
    try:
        with open(tmp_path, "wb") as f:
            f.write(plaintext)
        pdf.embed_file(tmp_path, desc="Decrypted result", compress=False)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        try:
            os.rmdir(tmp_dir)
        except OSError:
            pass
    buf = io.BytesIO()
    pdf.output(buf)
    return buf.getvalue()


def main() -> None:
    if len(sys.argv) >= 2 and sys.argv[1].lower() == "encrypt":
        if len(sys.argv) < 3:
            print("Usage: python cli.py encrypt <file>", file=sys.stderr)
            sys.exit(1)
        run_encrypt(sys.argv[2])
        return

    default_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "12.kuznyechik"
    )
    path = sys.argv[1] if len(sys.argv) > 1 else default_path
    if not os.path.isfile(path):
        print(f"File not found: {path}", file=sys.stderr)
        sys.exit(1)
    key, ciphertext = parse_kuznyechik_file(path)
    t_start = time.perf_counter()
    if len(ciphertext) >= PARALLEL_THRESHOLD:
        plaintext = ecb_decrypt_parallel(key, ciphertext, unpad=True)
    else:
        cipher = Kuznyechik(key, use_mi_tables=True)
        plaintext = ecb_decrypt(cipher, ciphertext, unpad=True)
    t_end = time.perf_counter()
    size_bytes = len(plaintext)
    time_sec = t_end - t_start
    speed_mb_s = (size_bytes / (1024 * 1024)) / time_sec if time_sec > 0 else 0.0
    size_mb = size_bytes / (1024 * 1024)
    print(
        f"Объём данных: {size_bytes} байт ({size_mb:.2f} МБ)",
        file=sys.stderr,
    )
    print(f"Время дешифровки: {time_sec:.3f} с", file=sys.stderr)
    print(f"Скорость: {speed_mb_s:.2f} МБ/с", file=sys.stderr)
    pdf_bytes = write_report_pdf(path, plaintext, size_bytes, time_sec, speed_mb_s)
    with open("output.pdf", "wb") as f:
        f.write(plaintext)

if __name__ == "__main__":
    main()
