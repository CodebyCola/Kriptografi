"""
XOR Cipher — logic murni (tidak ada kode Streamlit di sini).

Kenapa dipisah dari tampilan?
Supaya kalau nanti mau nambah menu algoritma lain (Caesar, Vigenere, DES, dst),
setiap algoritma cukup punya 1 file logic di folder ini + 1 file tampilan
di folder pages_ui/, tanpa main.py jadi tambah panjang.
"""

from dataclasses import dataclass


@dataclass
class XORStep:
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
class XORProcess:
    plaintext: str
    key: str

    plaintext_bytes: bytes
    key_bytes: bytes
    repeated_key: bytes

    steps: list[XORStep]

    ciphertext: bytes
    ciphertext_hex: str


def _safe_char(byte: int) -> str:
    """Ubah 1 byte jadi karakter yang aman ditampilkan di tabel/UI."""
    try:
        char = bytes([byte]).decode("utf-8")
    except UnicodeDecodeError:
        return "·"
    return char if char.isprintable() else "·"


def xor_encrypt(plaintext: str, key: str) -> bytes:
    """Enkripsi plaintext (str) -> ciphertext (bytes) dengan XOR + key berulang."""
    plaintext_bytes = plaintext.encode("utf-8")
    key_bytes = key.encode("utf-8")

    ciphertext = bytearray()
    for i, byte in enumerate(plaintext_bytes):
        key_byte = key_bytes[i % len(key_bytes)]
        ciphertext.append(byte ^ key_byte)

    return bytes(ciphertext)


def xor_decrypt(ciphertext: bytes, key: str) -> str:
    """Dekripsi ciphertext (bytes) -> plaintext (str) dengan XOR + key berulang."""
    key_bytes = key.encode("utf-8")

    plaintext = bytearray()
    for i, byte in enumerate(ciphertext):
        key_byte = key_bytes[i % len(key_bytes)]
        plaintext.append(byte ^ key_byte)

    return plaintext.decode("utf-8")


def get_xor_process(plaintext: str, key: str) -> XORProcess:
    """Jalankan enkripsi sambil merekam setiap langkah, untuk ditampilkan di UI."""
    plaintext_bytes = plaintext.encode("utf-8")
    key_bytes = key.encode("utf-8")

    steps: list[XORStep] = []
    repeated_key = bytearray()

    for i, plaintext_byte in enumerate(plaintext_bytes):
        key_byte = key_bytes[i % len(key_bytes)]
        ciphertext_byte = plaintext_byte ^ key_byte
        repeated_key.append(key_byte)

        steps.append(
            XORStep(
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

    return XORProcess(
        plaintext=plaintext,
        key=key,
        plaintext_bytes=plaintext_bytes,
        key_bytes=key_bytes,
        repeated_key=bytes(repeated_key),
        steps=steps,
        ciphertext=ciphertext,
        ciphertext_hex=ciphertext.hex(),
    )


def get_xor_decryption_process(ciphertext: bytes, key: str) -> list[XORStep]:
    """Jalankan dekripsi sambil merekam setiap langkah (struktur sama dengan enkripsi)."""
    key_bytes = key.encode("utf-8")
    steps: list[XORStep] = []

    for i, ciphertext_byte in enumerate(ciphertext):
        key_byte = key_bytes[i % len(key_bytes)]
        plaintext_byte = ciphertext_byte ^ key_byte

        steps.append(
            XORStep(
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
