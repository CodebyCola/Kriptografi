"""
ECB (Electronic Codebook) — logic murni (tidak ada kode Streamlit di sini).

ECB itu MODE OPERASI block cipher, bukan algoritma enkripsi itu sendiri.
Block cipher yang dipakai di sini adalah AES-128 (blok 16 byte), diambil dari
library `cryptography` — implementasi AES manual dari nol di luar cakupan
tugas ini, sama seperti tidak ada yang implementasi SHA-256 dari nol.

Cara kerja ECB, sesuai namanya "Electronic CODEBOOK":
1. Plaintext dipotong-potong jadi blok berukuran tetap (AES = 16 byte/blok).
2. Kalau panjang plaintext bukan kelipatan 16 byte, blok terakhir di-"pad"
   (diisi byte tambahan) pakai skema PKCS#7, supaya pas 16 byte.
3. SETIAP blok dienkripsi SENDIRI-SENDIRI pakai key yang SAMA, TANPA
   bergantung ke blok sebelum/sesudahnya (beda dengan mode CBC yang
   meng-XOR-kan blok sebelumnya ke blok sekarang).
4. Ciphertext = gabungan semua blok yang sudah dienkripsi, urut sesuai
   urutan aslinya.

Konsekuensi penting yang mau ditunjukkan di menu ini (kelemahan ECB):
karena tiap blok independen, BLOK PLAINTEXT YANG SAMA akan selalu
menghasilkan BLOK CIPHERTEXT YANG SAMA juga (selama key sama). Ini bikin
pola/struktur data asli masih "kelihatan" di ciphertext — makanya ECB
umumnya TIDAK disarankan untuk data yang punya banyak blok berulang
(mode lain seperti CBC/CTR/GCM memakai IV/nonce supaya blok yang sama
tetap menghasilkan ciphertext yang beda-beda).

Kenapa dipisah dari tampilan? Supaya konsisten dengan pola cipher lain di
folder ini (lihat vernam_chiper.py) — 1 file logic di sini + 1 file tampilan di
pages_ui/.
"""

import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE = 16  # AES selalu punya ukuran blok 16 byte, berapapun panjang key-nya.
KEY_SIZE = 16  # AES-128 -> key 16 byte (128 bit).


@dataclass
class ECBBlockStep:
    index: int

    plaintext_block: bytes
    ciphertext_block: bytes

    plaintext_block_hex: str
    ciphertext_block_hex: str

    is_padding_block: bool
    # True kalau isi blok plaintext-nya sama persis dengan salah satu blok
    # SEBELUMNYA -> dipakai untuk menunjukkan kelemahan ECB (blok sama,
    # hasil enkripsi juga pasti sama).
    duplicate_of_index: int | None


@dataclass
class ECBProcess:
    plaintext: str
    key_hex: str

    plaintext_bytes: bytes
    padded_bytes: bytes
    padding_length: int

    blocks: list[ECBBlockStep]

    ciphertext: bytes
    ciphertext_hex: str


def generate_random_key(length: int = KEY_SIZE) -> bytes:
    """Buat key AES acak sepanjang `length` byte (default 16 byte / AES-128)."""
    return secrets.token_bytes(length)


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """
    Tambah padding PKCS#7 supaya panjang `data` jadi kelipatan `block_size`.

    Aturannya: tambahkan N byte, masing-masing bernilai N, di mana N adalah
    jumlah byte yang kurang supaya genap satu blok. Kalau `data` KEBETULAN
    sudah pas kelipatan block_size, tetap ditambah 1 blok penuh berisi
    byte bernilai block_size — supaya proses unpad tidak ambigu.
    """
    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length]) * padding_length


def pkcs7_unpad(data: bytes) -> bytes:
    """Buang padding PKCS#7 yang ditambahkan oleh `pkcs7_pad`."""
    if not data:
        raise ValueError("Data kosong, tidak ada padding untuk dibuang.")

    padding_length = data[-1]
    if padding_length == 0 or padding_length > len(data):
        raise ValueError("Padding PKCS#7 tidak valid.")

    if data[-padding_length:] != bytes([padding_length]) * padding_length:
        raise ValueError("Padding PKCS#7 tidak valid (byte padding tidak seragam).")

    return data[:-padding_length]


def _split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> list[bytes]:
    return [data[i : i + block_size] for i in range(0, len(data), block_size)]


def _aes_encrypt_block(block: bytes, key: bytes) -> bytes:
    """
    Enkripsi SATU blok (16 byte) pakai AES, mode ECB.

    Dipanggil satu-satu per blok (bukan sekali untuk semua data) supaya
    kelihatan jelas kalau ECB memang memperlakukan tiap blok sebagai unit
    yang berdiri sendiri, tidak ada state yang dibawa dari blok sebelumnya.
    """
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def _aes_decrypt_block(block: bytes, key: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return decryptor.update(block) + decryptor.finalize()


def ecb_encrypt_bytes(data: bytes, key: bytes) -> bytes:
    """Enkripsi bytes mentah dengan AES-128-ECB + PKCS#7 padding."""
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key harus {KEY_SIZE} byte (AES-128), key yang diberikan {len(key)} byte.")

    padded = pkcs7_pad(data)
    ciphertext = bytearray()
    for block in _split_blocks(padded):
        ciphertext.extend(_aes_encrypt_block(block, key))
    return bytes(ciphertext)


def ecb_encrypt(plaintext: str, key: bytes) -> bytes:
    """Enkripsi plaintext (str) -> ciphertext (bytes) dengan AES-ECB."""
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key harus {KEY_SIZE} byte (AES-128), key yang diberikan {len(key)} byte.")

    padded = pkcs7_pad(plaintext.encode("utf-8"))

    ciphertext = bytearray()
    for block in _split_blocks(padded):
        ciphertext.extend(_aes_encrypt_block(block, key))

    return bytes(ciphertext)


def ecb_decrypt_bytes(ciphertext: bytes, key: bytes) -> bytes:
    """Dekripsi bytes dengan AES-128-ECB lalu buang PKCS#7 padding."""
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key harus {KEY_SIZE} byte (AES-128), key yang diberikan {len(key)} byte.")
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(f"Panjang ciphertext harus kelipatan {BLOCK_SIZE} byte (bukan blok AES yang valid).")
    if len(ciphertext) == 0:
        raise ValueError("Ciphertext tidak boleh kosong.")

    padded = bytearray()
    for block in _split_blocks(ciphertext):
        padded.extend(_aes_decrypt_block(block, key))

    return pkcs7_unpad(bytes(padded))


def ecb_decrypt(ciphertext: bytes, key: bytes) -> str:
    """Dekripsi ciphertext (bytes) -> plaintext (str) dengan AES-ECB."""
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key harus {KEY_SIZE} byte (AES-128), key yang diberikan {len(key)} byte.")
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(f"Panjang ciphertext harus kelipatan {BLOCK_SIZE} byte (bukan blok AES yang valid).")
    if len(ciphertext) == 0:
        raise ValueError("Ciphertext tidak boleh kosong.")

    padded = bytearray()
    for block in _split_blocks(ciphertext):
        padded.extend(_aes_decrypt_block(block, key))

    plaintext_bytes = pkcs7_unpad(bytes(padded))
    return plaintext_bytes.decode("utf-8")


def get_ecb_process(plaintext: str, key: bytes) -> ECBProcess:
    """Jalankan enkripsi sambil merekam tiap blok, untuk ditampilkan di UI."""
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key harus {KEY_SIZE} byte (AES-128), key yang diberikan {len(key)} byte.")

    plaintext_bytes = plaintext.encode("utf-8")
    padding_length = BLOCK_SIZE - (len(plaintext_bytes) % BLOCK_SIZE)
    padded = pkcs7_pad(plaintext_bytes)

    plaintext_blocks = _split_blocks(padded)
    num_full_blocks = len(plaintext_bytes) // BLOCK_SIZE  # blok yang isinya 100% data asli

    blocks: list[ECBBlockStep] = []
    seen_blocks: dict[bytes, int] = {}

    for i, plaintext_block in enumerate(plaintext_blocks):
        ciphertext_block = _aes_encrypt_block(plaintext_block, key)

        duplicate_of_index = seen_blocks.get(plaintext_block)
        if duplicate_of_index is None:
            seen_blocks[plaintext_block] = i

        blocks.append(
            ECBBlockStep(
                index=i,
                plaintext_block=plaintext_block,
                ciphertext_block=ciphertext_block,
                plaintext_block_hex=plaintext_block.hex(),
                ciphertext_block_hex=ciphertext_block.hex(),
                is_padding_block=i >= num_full_blocks,
                duplicate_of_index=duplicate_of_index,
            )
        )

    ciphertext = b"".join(step.ciphertext_block for step in blocks)

    return ECBProcess(
        plaintext=plaintext,
        key_hex=key.hex(),
        plaintext_bytes=plaintext_bytes,
        padded_bytes=padded,
        padding_length=padding_length,
        blocks=blocks,
        ciphertext=ciphertext,
        ciphertext_hex=ciphertext.hex(),
    )


def get_ecb_decryption_process(ciphertext: bytes, key: bytes) -> list[ECBBlockStep]:
    """Jalankan dekripsi sambil merekam tiap blok (struktur sama dengan enkripsi)."""
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key harus {KEY_SIZE} byte (AES-128), key yang diberikan {len(key)} byte.")
    if len(ciphertext) % BLOCK_SIZE != 0 or len(ciphertext) == 0:
        raise ValueError(f"Panjang ciphertext harus kelipatan {BLOCK_SIZE} byte dan tidak boleh kosong.")

    blocks: list[ECBBlockStep] = []
    seen_blocks: dict[bytes, int] = {}

    for i, ciphertext_block in enumerate(_split_blocks(ciphertext)):
        plaintext_block = _aes_decrypt_block(ciphertext_block, key)

        duplicate_of_index = seen_blocks.get(ciphertext_block)
        if duplicate_of_index is None:
            seen_blocks[ciphertext_block] = i

        blocks.append(
            ECBBlockStep(
                index=i,
                plaintext_block=plaintext_block,
                ciphertext_block=ciphertext_block,
                plaintext_block_hex=plaintext_block.hex(),
                ciphertext_block_hex=ciphertext_block.hex(),
                is_padding_block=(i == len(ciphertext) // BLOCK_SIZE - 1),
                duplicate_of_index=duplicate_of_index,
            )
        )

    return blocks