

from dataclasses import dataclass

from ciphers.caesar_cipher import caesar_encrypt, caesar_decrypt
from ciphers.vigenere_cipher import vigenere_encrypt, vigenere_decrypt
from ciphers.xor_cipher import xor_encrypt, xor_decrypt
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
    xor_key: str

    after_caesar: str
    after_vigenere: str
    after_xor: bytes
    after_vernam: bytes  # = ciphertext akhir

    vernam_key: bytes  # key OTP yang di-generate otomatis, wajib disimpan user

    @property
    def ciphertext(self) -> bytes:
        return self.after_vernam

    @property
    def ciphertext_hex(self) -> str:
        return self.after_vernam.hex()

    @property
    def vernam_key_hex(self) -> str:
        return self.vernam_key.hex()

    @property
    def after_xor_hex(self) -> str:
        return self.after_xor.hex()


@dataclass
class SuperDecryptResult:
    ciphertext: bytes

    caesar_shift: int
    vigenere_key: str
    xor_key: str
    vernam_key: bytes

    after_vernam: bytes  # = hasil balik Vernam = sama dengan after_xor saat enkripsi
    after_xor: str       # = hasil balik XOR = sama dengan after_vigenere saat enkripsi
    after_vigenere: str  # = hasil balik Vigenere = sama dengan after_caesar saat enkripsi
    after_caesar: str    # = plaintext asli

    @property
    def plaintext(self) -> str:
        return self.after_caesar

    @property
    def after_vernam_hex(self) -> str:
        return self.after_vernam.hex()


# ============================================================
# Validasi kunci (dipusatkan di sini supaya pesan error konsisten)
# ============================================================

def validate_super_keys(vigenere_key: str, xor_key: str) -> str | None:
    """Cek kunci Vigenere & XOR sebelum dipakai. Return pesan error, atau None kalau valid."""
    if not vigenere_key or not vigenere_key.isalpha() or not vigenere_key.isascii():
        return "Kunci Vigenere harus berupa huruf A-Z dan tidak kosong."
    if not xor_key:
        return "Kunci XOR tidak boleh kosong."
    return None


# ============================================================
# Enkripsi berantai
# ============================================================

def super_encrypt(
    plaintext: str,
    caesar_shift: int,
    vigenere_key: str,
    xor_key: str,
    vernam_key: bytes | None = None,
) -> SuperEncryptResult:
    """
    Jalankan 4 algoritma berurutan: Caesar -> Vigenere -> XOR -> Vernam.

    vernam_key opsional: kalau tidak diisi, di-generate otomatis secara acak
    sepanjang hasil tahap XOR (mengikuti syarat one-time pad). Kalau diisi
    (misalnya saat menguji ulang / reproduksi hasil), panjangnya WAJIB sama
    dengan hasil tahap XOR, kalau tidak akan raise ValueError (sama seperti
    perilaku vernam_encrypt()).
    """
    step1 = caesar_encrypt(plaintext, caesar_shift)
    step2 = vigenere_encrypt(step1, vigenere_key)
    step3 = xor_encrypt(step2, xor_key)

    key_otp = vernam_key if vernam_key is not None else generate_random_key(len(step3))
    step4 = _vernam_xor_bytes(step3, key_otp)

    return SuperEncryptResult(
        plaintext=plaintext,
        caesar_shift=caesar_shift,
        vigenere_key=vigenere_key,
        xor_key=xor_key,
        after_caesar=step1,
        after_vigenere=step2,
        after_xor=step3,
        after_vernam=step4,
        vernam_key=key_otp,
    )


# ============================================================
# Dekripsi berantai (urutan kebalikan dari enkripsi)
# ============================================================

def super_decrypt(
    ciphertext: bytes,
    caesar_shift: int,
    vigenere_key: str,
    xor_key: str,
    vernam_key: bytes,
) -> SuperDecryptResult:
    """
    Bongkar ciphertext dengan urutan terbalik: Vernam -> XOR -> Vigenere -> Caesar.

    Semua kunci (termasuk vernam_key hasil generate saat enkripsi) wajib
    persis sama dengan yang dipakai saat enkripsi, kalau tidak hasil akhirnya
    tidak akan jadi plaintext yang benar (atau bisa gagal di-decode UTF-8).
    """
    step1 = _vernam_xor_bytes(ciphertext, vernam_key)         # bytes -> bytes
    step2 = xor_decrypt(step1, xor_key)                      # bytes -> str
    step3 = vigenere_decrypt(step2, vigenere_key)             # str -> str
    step4 = caesar_decrypt(step3, caesar_shift)                # str -> str

    return SuperDecryptResult(
        ciphertext=ciphertext,
        caesar_shift=caesar_shift,
        vigenere_key=vigenere_key,
        xor_key=xor_key,
        vernam_key=vernam_key,
        after_vernam=step1,
        after_xor=step2,
        after_vigenere=step3,
        after_caesar=step4,
    )
