"""
Caesar Cipher — logic murni (tidak ada kode Streamlit di sini).

Caesar Cipher menggeser tiap huruf sejauh `shift` posisi di alfabet.
Karakter non-huruf (spasi, angka, tanda baca) dibiarkan apa adanya.

Enkripsi: C = (P + shift) mod 26
Dekripsi: P = (C - shift) mod 26
"""

from dataclasses import dataclass


@dataclass
class CaesarStep:
    index: int

    original_char: str
    key_char: str          
    shift_used: int        
    result_char: str       
    is_alpha: bool


def caesar_encrypt(plaintext: str, shift: int) -> str:
    shift = shift % 26
    hasil = ""
    for ch in plaintext:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            hasil += chr((ord(ch) - base + shift) % 26 + base)
        else:
            hasil += ch
    return hasil


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    return caesar_encrypt(ciphertext, -shift)


def get_caesar_process(text: str, shift: int, mode: str = "encrypt") -> list[CaesarStep]:
    """
    Rekam proses geser huruf per karakter, untuk ditampilkan di UI.

    mode="encrypt" -> geser maju sejauh `shift`
    mode="decrypt" -> geser mundur sejauh `shift` (dipanggil dengan teks ciphertext)
    """
    actual_shift = shift if mode == "encrypt" else -shift
    actual_shift = actual_shift % 26

    steps: list[CaesarStep] = []
    for i, ch in enumerate(text):
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            result = chr((ord(ch) - base + actual_shift) % 26 + base)
            steps.append(
                CaesarStep(
                    index=i,
                    original_char=ch,
                    key_char="-",  
                    shift_used=actual_shift,
                    result_char=result,
                    is_alpha=True,
                )
            )
        else:
            steps.append(
                CaesarStep(
                    index=i,
                    original_char=ch,
                    key_char="-",
                    shift_used=0,
                    result_char=ch,
                    is_alpha=False,
                )
            )
    return steps
