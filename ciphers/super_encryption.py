"""
Logic Super Enkripsi.

Urutan enkripsi:
    Caesar -> Vigenere -> Vernam

Urutan dekripsi:
    Vernam -> Vigenere -> Caesar

Setiap algoritma tetap dipisahkan di modulnya masing-masing supaya logic
super enkripsi hanya bertugas mengorkestrasi pipeline.
"""

from dataclasses import dataclass

from ciphers.caesar_cipher import caesar_encrypt, caesar_decrypt
from ciphers.vigenere_cipher import vigenere_encrypt, vigenere_decrypt
from ciphers.vernam_chiper import generate_random_key


def _vernam_xor_bytes(data: bytes, key: bytes) -> bytes:
    if len(key) != len(data):
        raise ValueError(
            f"Panjang key Vernam ({len(key)} byte) harus sama persis dengan "
            f"panjang data pada tahap itu ({len(data)} byte)."
        )
    return bytes(b ^ k for b, k in zip(data, key))


@dataclass
class SuperEncryptResult:
    plaintext: str

    caesar_shift: int
    vigenere_key: str

    after_caesar: str
    after_vigenere: str
    after_vernam: bytes

    vernam_key: bytes

    @property
    def ciphertext(self) -> bytes:
        return self.after_vernam

    @property
    def ciphertext_hex(self) -> str:
        return self.after_vernam.hex()

    @property
    def vernam_key_hex(self) -> str:
        return self.vernam_key.hex()


@dataclass
class SuperDecryptResult:
    ciphertext: bytes

    caesar_shift: int
    vigenere_key: str
    vernam_key: bytes

    after_vernam: str
    after_vigenere: str
    after_caesar: str

    @property
    def plaintext(self) -> str:
        return self.after_caesar

    @property
    def after_vernam_hex(self) -> str:
        return self.after_vernam.encode("utf-8").hex()


# ============================================================
# Validasi kunci
# ============================================================

def validate_super_keys(vigenere_key: str) -> str | None:
    """Validasi kunci Vigenere sebelum pipeline dijalankan."""
    if not vigenere_key or not vigenere_key.isalpha() or not vigenere_key.isascii():
        return "Kunci Vigenere harus berupa huruf A-Z dan tidak kosong."
    return None


# ============================================================
# Enkripsi berantai
# ============================================================

def super_encrypt(
    plaintext: str,
    caesar_shift: int,
    vigenere_key: str,
    vernam_key: bytes | None = None,
) -> SuperEncryptResult:
    """
    Jalankan 3 algoritma berurutan: Caesar -> Vigenere -> Vernam.

    Key Vernam opsional. Jika tidak diberikan, key acak dibuat otomatis
    sepanjang hasil tahap Vigenere dalam byte UTF-8.
    """
    step1 = caesar_encrypt(plaintext, caesar_shift)
    step2 = vigenere_encrypt(step1, vigenere_key)

    step2_bytes = step2.encode("utf-8")
    key_otp = vernam_key if vernam_key is not None else generate_random_key(len(step2_bytes))
    step3 = _vernam_xor_bytes(step2_bytes, key_otp)

    return SuperEncryptResult(
        plaintext=plaintext,
        caesar_shift=caesar_shift,
        vigenere_key=vigenere_key,
        after_caesar=step1,
        after_vigenere=step2,
        after_vernam=step3,
        vernam_key=key_otp,
    )


# ============================================================
# Dekripsi berantai
# ============================================================

def super_decrypt(
    ciphertext: bytes,
    caesar_shift: int,
    vigenere_key: str,
    vernam_key: bytes,
) -> SuperDecryptResult:
    """
    Bongkar ciphertext dengan urutan terbalik: Vernam -> Vigenere -> Caesar.
    """
    step1_bytes = _vernam_xor_bytes(ciphertext, vernam_key)
    step1 = step1_bytes.decode("utf-8")
    step2 = vigenere_decrypt(step1, vigenere_key)
    step3 = caesar_decrypt(step2, caesar_shift)

    return SuperDecryptResult(
        ciphertext=ciphertext,
        caesar_shift=caesar_shift,
        vigenere_key=vigenere_key,
        vernam_key=vernam_key,
        after_vernam=step1,
        after_vigenere=step2,
        after_caesar=step3,
    )
