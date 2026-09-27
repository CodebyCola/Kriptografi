"""
Vernam Cipher (One-Time Pad) — logic murni (tidak ada kode Streamlit di sini).

Vernam menggunakan operasi XOR per byte. Karakteristik One-Time Pad
memerlukan tiga syarat pada key: panjangnya sama dengan data, key benar-benar
acak, dan key tidak digunakan ulang.

Logic dipisahkan dari tampilan agar dapat digunakan ulang oleh halaman Vernam
dan pipeline Super Enkripsi.
"""

import secrets
from dataclasses import dataclass


@dataclass
class VernamStep:
    index: int

    plaintext_char: str
    key_char: str

    plaintext_byte: int
    key_byte: int
    ciphertext_byte: int

    plaintext_binary: str
    key_binary: str
    ciphertext_binary: str


@dataclass
class VernamProcess:
    plaintext: str
    key_hex: str

    plaintext_bytes: bytes
    key_bytes: bytes

    steps: list[VernamStep]

    ciphertext: bytes
    ciphertext_hex: str


def _safe_char(byte: int) -> str:
    """Ubah 1 byte jadi karakter yang aman ditampilkan di tabel/UI."""
    try:
        char = bytes([byte]).decode("utf-8")
    except UnicodeDecodeError:
        return "·"
    return char if char.isprintable() else "·"


def generate_random_key(length: int) -> bytes:
    """
    Buat key one-time pad yang benar-benar acak sepanjang `length` byte.

    Pakai `secrets` (bukan `random`) karena ini modul khusus Python untuk
    kebutuhan kriptografi — hasilnya cryptographically secure, bukan cuma
    acak semu (pseudo-random) seperti modul `random` biasa.
    """
    return secrets.token_bytes(length)


def vernam_encrypt(plaintext: str, key: bytes) -> bytes:
    """
    Enkripsi plaintext (str) -> ciphertext (bytes) dengan Vernam Cipher.

    Key Vernam TIDAK diulang. Panjang key wajib sama persis dengan panjang
    plaintext (dalam byte UTF-8), kalau tidak dianggap error.
    """
    plaintext_bytes = plaintext.encode("utf-8")

    if len(key) != len(plaintext_bytes):
        raise ValueError(
            f"Panjang key ({len(key)} byte) harus sama persis dengan "
            f"panjang plaintext ({len(plaintext_bytes)} byte) pada Vernam Cipher."
        )

    ciphertext = bytearray()
    for plaintext_byte, key_byte in zip(plaintext_bytes, key):
        ciphertext.append(plaintext_byte ^ key_byte)

    return bytes(ciphertext)


def vernam_decrypt(ciphertext: bytes, key: bytes) -> str:
    """Dekripsi ciphertext (bytes) -> plaintext (str) dengan Vernam Cipher."""
    if len(key) != len(ciphertext):
        raise ValueError(
            f"Panjang key ({len(key)} byte) harus sama persis dengan "
            f"panjang ciphertext ({len(ciphertext)} byte) pada Vernam Cipher."
        )

    plaintext = bytearray()
    for ciphertext_byte, key_byte in zip(ciphertext, key):
        plaintext.append(ciphertext_byte ^ key_byte)

    return plaintext.decode("utf-8")


def get_vernam_process(plaintext: str, key: bytes) -> VernamProcess:
    """Jalankan enkripsi sambil merekam setiap langkah, untuk ditampilkan di UI."""
    plaintext_bytes = plaintext.encode("utf-8")

    if len(key) != len(plaintext_bytes):
        raise ValueError(
            f"Panjang key ({len(key)} byte) harus sama persis dengan "
            f"panjang plaintext ({len(plaintext_bytes)} byte) pada Vernam Cipher."
        )

    steps: list[VernamStep] = []

    for i, plaintext_byte in enumerate(plaintext_bytes):
        key_byte = key[i]
        ciphertext_byte = plaintext_byte ^ key_byte

        steps.append(
            VernamStep(
                index=i,
                plaintext_char=_safe_char(plaintext_byte),
                key_char=_safe_char(key_byte),
                plaintext_byte=plaintext_byte,
                key_byte=key_byte,
                ciphertext_byte=ciphertext_byte,
                plaintext_binary=f"{plaintext_byte:08b}",
                key_binary=f"{key_byte:08b}",
                ciphertext_binary=f"{ciphertext_byte:08b}",
            )
        )

    ciphertext = bytes(step.ciphertext_byte for step in steps)

    return VernamProcess(
        plaintext=plaintext,
        key_hex=key.hex(),
        plaintext_bytes=plaintext_bytes,
        key_bytes=key,
        steps=steps,
        ciphertext=ciphertext,
        ciphertext_hex=ciphertext.hex(),
    )


def get_vernam_decryption_process(ciphertext: bytes, key: bytes) -> list[VernamStep]:
    """Jalankan dekripsi sambil merekam setiap langkah (struktur sama dengan enkripsi)."""
    if len(key) != len(ciphertext):
        raise ValueError(
            f"Panjang key ({len(key)} byte) harus sama persis dengan "
            f"panjang ciphertext ({len(ciphertext)} byte) pada Vernam Cipher."
        )

    steps: list[VernamStep] = []

    for i, ciphertext_byte in enumerate(ciphertext):
        key_byte = key[i]
        plaintext_byte = ciphertext_byte ^ key_byte

        steps.append(
            VernamStep(
                index=i,
                plaintext_char=_safe_char(plaintext_byte),
                key_char=_safe_char(key_byte),
                plaintext_byte=plaintext_byte,
                key_byte=key_byte,
                ciphertext_byte=ciphertext_byte,
                plaintext_binary=f"{plaintext_byte:08b}",
                key_binary=f"{key_byte:08b}",
                ciphertext_binary=f"{ciphertext_byte:08b}",
            )
        )

    return steps