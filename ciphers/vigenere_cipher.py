"""
Vigenere Cipher

Plaintext dienkripsi dengan pergeseran huruf berdasarkan kunci berulang.
Dekripsi membalik proses tersebut.
"""

from dataclasses import dataclass


@dataclass
class VigenereStep:
    index: int
    original_char: str
    key_char: str
    key_index: int
    shift: int
    result_char: str
    is_alpha: bool
    target_index: int


def _validate_key(key: str) -> str:
    if not key or not key.isalpha() or not key.isascii():
        raise ValueError("Kunci harus berupa huruf A-Z dan tidak kosong")
    return key


def _key_shift(key_char: str) -> int:
    return ord(key_char.upper()) - ord("A")


def _shift_char(ch: str, shift: int) -> str:
    if not ch.isalpha():
        return ch

    base = ord("A") if ch.isupper() else ord("a")
    return chr((ord(ch) - base + shift) % 26 + base)


def _unshift_char(ch: str, shift: int) -> str:
    return _shift_char(ch, -shift)


def vigenere_encrypt(plaintext: str, key: str) -> str:
    key = _validate_key(key)

    result = []
    key_pos = 0

    for ch in plaintext:
        if ch.isalpha():
            shift = _key_shift(key[key_pos % len(key)])
            result.append(_shift_char(ch, shift))
            key_pos += 1
        else:
            result.append(ch)

    return "".join(result)


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    key = _validate_key(key)

    result = []
    key_pos = 0

    for ch in ciphertext:
        if ch.isalpha():
            shift = _key_shift(key[key_pos % len(key)])
            result.append(_unshift_char(ch, shift))
            key_pos += 1
        else:
            result.append(ch)

    return "".join(result)


def get_vigenere_process(
    text: str,
    key: str,
    mode: str = "encrypt"
) -> list[VigenereStep]:
    """
    Rekam proses Vigenere per karakter untuk ditampilkan di UI.

    mode="encrypt" -> text adalah plaintext
    mode="decrypt" -> text adalah ciphertext
    """
    key = _validate_key(key)

    if mode not in ("encrypt", "decrypt"):
        raise ValueError("mode harus 'encrypt' atau 'decrypt'")

    steps = []
    key_pos = 0

    for i, ch in enumerate(text):
        if ch.isalpha():
            key_index = key_pos % len(key)
            key_char = key[key_index]
            shift = _key_shift(key_char)

            if mode == "encrypt":
                result_char = _shift_char(ch, shift)
            else:
                result_char = _unshift_char(ch, shift)

            key_pos += 1
            is_alpha = True
        else:
            key_index = -1
            key_char = ""
            shift = 0
            result_char = ch
            is_alpha = False

        steps.append(
            VigenereStep(
                index=i,
                original_char=ch,
                key_char=key_char,
                key_index=key_index,
                shift=shift,
                result_char=result_char,
                is_alpha=is_alpha,
                target_index=i,
            )
        )

    return steps