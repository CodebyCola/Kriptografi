"""
Vernam Cipher (One-Time Pad) — logic murni (tidak ada kode Streamlit di sini).

Apa bedanya dengan XOR Cipher biasa (ciphers/xor_cipher.py)?
Operasinya SAMA PERSIS (XOR per byte), tapi syarat key-nya BEDA dan itulah
yang membuat Vernam Cipher istimewa (perfect secrecy - Shannon, 1949):

1. Key HARUS sama panjang dengan plaintext (tidak boleh diulang/repeating,
   beda dengan XOR Cipher di menu sebelah yang key-nya boleh lebih pendek).
2. Key harus BENAR-BENAR ACAK (bukan kata/kalimat bermakna).
3. Key HANYA BOLEH dipakai SEKALI lalu dibuang (makanya disebut "one-time pad").

Kalau salah satu dari 3 syarat itu dilanggar, ini bukan Vernam Cipher lagi,
cuma XOR Cipher dengan key sepanjang plaintext.

Kenapa dipisah dari tampilan? Supaya konsisten dengan pola cipher lain di
folder ini (lihat xor_cipher.py) — 1 file logic di sini + 1 file tampilan
di pages_ui/, tanpa main.py jadi tambah panjang.
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

    Beda dengan xor_encrypt(): key di sini TIDAK diulang. Panjang key wajib
    sama persis dengan panjang plaintext (dalam byte UTF-8), kalau tidak
    dianggap error supaya syarat one-time pad tidak dilanggar diam-diam.
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