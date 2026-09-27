"""Logic Super Enkripsi.

Pipeline:
    Enkripsi : Plaintext -> Caesar -> Vigenere -> Vernam -> AES-128-ECB
    Dekripsi : Ciphertext -> AES-128-ECB -> Vernam -> Vigenere -> Caesar

Caesar dan Vigenere bekerja pada huruf A-Z/a-z dan mempertahankan karakter
lainnya. Hasil Vigenere kemudian diubah menjadi UTF-8 bytes untuk Vernam.
Vernam melakukan XOR byte-per-byte tanpa mengulang key. Hasil XOR yang masih
berupa bytes kemudian dienkripsi dengan AES-128 dalam mode ECB.
"""

from dataclasses import dataclass

from ciphers.caesar_cipher import caesar_decrypt, caesar_encrypt
from ciphers.ecb_cipher import (
    BLOCK_SIZE,
    KEY_SIZE,
    ecb_decrypt_bytes,
    ecb_encrypt_bytes,
    generate_random_key as generate_ecb_key,
)
from ciphers.vernam_chiper import generate_random_key as generate_vernam_key
from ciphers.vigenere_cipher import vigenere_decrypt, vigenere_encrypt


@dataclass
class SuperEncryptResult:
    plaintext: str
    caesar_shift: int
    vigenere_key: str

    after_caesar: str
    after_vigenere: str
    after_vigenere_bytes: bytes

    vernam_key: bytes
    vernam_key_hex: str
    after_vernam: bytes
    after_vernam_hex: str

    ecb_key: bytes
    ecb_key_hex: str
    ciphertext: bytes
    ciphertext_hex: str


@dataclass
class SuperDecryptResult:
    ciphertext: bytes
    ecb_key: bytes
    vernam_key: bytes
    caesar_shift: int
    vigenere_key: str

    after_ecb: bytes
    after_ecb_hex: str
    after_vernam: bytes
    after_vernam_hex: str
    after_vernam_text: str
    after_vigenere: str
    plaintext: str



def _xor_bytes(data: bytes, key: bytes) -> bytes:
    if len(data) != len(key):
        raise ValueError(
            f"Panjang key Vernam ({len(key)} byte) harus sama persis dengan "
            f"data ({len(data)} byte)."
        )
    return bytes(data_byte ^ key_byte for data_byte, key_byte in zip(data, key))


def validate_ecb_key(key: bytes) -> str | None:
    if len(key) != KEY_SIZE:
        return f"Key AES-ECB harus tepat {KEY_SIZE} byte (32 karakter HEX)."
    return None


def validate_hex_key(value: str, label: str) -> bytes:
    value = value.strip()
    if not value:
        raise ValueError(f"{label} tidak boleh kosong.")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{label} harus berupa HEX yang valid.") from exc


def _validate_vigenere_key(key: str) -> str:
    key = key.strip()
    if not key or not key.isalpha() or not key.isascii():
        raise ValueError("Kunci Vigenere harus berupa huruf A-Z dan tidak kosong.")
    return key


def super_encrypt(
    plaintext: str,
    caesar_shift: int,
    vigenere_key: str,
    ecb_key: bytes,
    vernam_key: bytes | None = None,
) -> SuperEncryptResult:
    """Jalankan Caesar -> Vigenere -> Vernam -> AES-ECB."""
    error = validate_ecb_key(ecb_key)
    if error:
        raise ValueError(error)

    vigenere_key = _validate_vigenere_key(vigenere_key)

    after_caesar = caesar_encrypt(plaintext, caesar_shift)
    after_vigenere = vigenere_encrypt(after_caesar, vigenere_key)
    after_vigenere_bytes = after_vigenere.encode("utf-8")

    vernam_key_value = (
        vernam_key
        if vernam_key is not None
        else generate_vernam_key(len(after_vigenere_bytes))
    )
    after_vernam = _xor_bytes(after_vigenere_bytes, vernam_key_value)

    ciphertext = ecb_encrypt_bytes(after_vernam, ecb_key)

    return SuperEncryptResult(
        plaintext=plaintext,
        caesar_shift=caesar_shift,
        vigenere_key=vigenere_key,
        after_caesar=after_caesar,
        after_vigenere=after_vigenere,
        after_vigenere_bytes=after_vigenere_bytes,
        vernam_key=vernam_key_value,
        vernam_key_hex=vernam_key_value.hex(),
        after_vernam=after_vernam,
        after_vernam_hex=after_vernam.hex(),
        ecb_key=ecb_key,
        ecb_key_hex=ecb_key.hex(),
        ciphertext=ciphertext,
        ciphertext_hex=ciphertext.hex(),
    )


def super_decrypt(
    ciphertext: bytes,
    caesar_shift: int,
    vigenere_key: str,
    ecb_key: bytes,
    vernam_key: bytes,
) -> SuperDecryptResult:
    """Bongkar ciphertext dengan urutan terbalik: ECB -> Vernam -> Vigenere -> Caesar."""
    if not ciphertext:
        raise ValueError("Ciphertext tidak boleh kosong.")

    error = validate_ecb_key(ecb_key)
    if error:
        raise ValueError(error)

    vigenere_key = _validate_vigenere_key(vigenere_key)

    if len(vernam_key) == 0:
        raise ValueError("Key Vernam tidak boleh kosong.")

    after_ecb = ecb_decrypt_bytes(ciphertext, ecb_key)

    if len(vernam_key) != len(after_ecb):
        raise ValueError(
            f"Panjang key Vernam ({len(vernam_key)} byte) harus sama persis "
            f"dengan hasil setelah ECB ({len(after_ecb)} byte)."
        )

    after_vernam = _xor_bytes(after_ecb, vernam_key)

    try:
        after_vernam_text = after_vernam.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(
            "Hasil Vernam bukan UTF-8 yang valid. Pastikan key Vernam, key ECB, "
            "dan ciphertext yang digunakan sama dengan saat enkripsi."
        ) from exc

    after_vigenere = vigenere_decrypt(after_vernam_text, vigenere_key)
    plaintext = caesar_decrypt(after_vigenere, caesar_shift)

    return SuperDecryptResult(
        ciphertext=ciphertext,
        ecb_key=ecb_key,
        vernam_key=vernam_key,
        caesar_shift=caesar_shift,
        vigenere_key=vigenere_key,
        after_ecb=after_ecb,
        after_ecb_hex=after_ecb.hex(),
        after_vernam=after_vernam,
        after_vernam_hex=after_vernam.hex(),
        after_vernam_text=after_vernam_text,
        after_vigenere=after_vigenere,
        plaintext=plaintext,
    )
