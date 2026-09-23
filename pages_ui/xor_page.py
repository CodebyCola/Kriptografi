"""
Halaman menu: XOR Cipher (Algoritma Modern).

Alur baca kode di file ini:
1. render()          -> dipanggil dari main.py
2. _tab_encrypt()     -> isi tab Enkripsi
3. _tab_decrypt()     -> isi tab Dekripsi
Keduanya sengaja ditulis dengan struktur SAMA PERSIS (flow -> tahap 1..5)
supaya alurnya gampang dibandingkan dan gampang dipresentasikan.
"""

import streamlit as st

from ciphers.xor_cipher import (
    xor_decrypt,
    get_xor_process,
    get_xor_decryption_process,
)
from ui_components import (
    flow_diagram,
    xor_step_table,
    xor_step_detail,
    bytes_as_hex,
    bytes_as_binary,
    printable_preview,
)

ENCRYPT_STAGES = [
    ("1", "Plaintext", "Teks input"),
    ("2", "UTF-8", "Konversi ke byte"),
    ("3", "Key berulang", "Key diulang sepanjang plaintext"),
    ("4", "XOR", "P ⊕ K per byte"),
    ("5", "Ciphertext", "Hasil enkripsi (HEX)"),
]

DECRYPT_STAGES = [
    ("1", "Ciphertext", "Input dalam format HEX"),
    ("2", "Bytes", "HEX → byte"),
    ("3", "Key berulang", "Key diulang sepanjang ciphertext"),
    ("4", "XOR", "C ⊕ K per byte"),
    ("5", "Plaintext", "Hasil dekripsi"),
]


def render():
    st.title("🔐 XOR Cipher")
    st.caption("Algoritma Kriptografi Modern — Materi 5")

    st.info("Enkripsi: **C = P ⊕ K**   |   Dekripsi: **P = C ⊕ K**")

    with st.expander("ℹ️ Cara kerja singkat", expanded=False):
        st.markdown(
            "- Plaintext & key diubah menjadi byte (UTF-8).\n"
            "- Jika key lebih pendek dari plaintext, key **diulang** secara periodik "
            "(mirip Vigenère Cipher, bedanya operasinya XOR bit, bukan geser huruf).\n"
            "- Setiap byte plaintext di-XOR dengan byte key pada posisi yang sama.\n"
            "- XOR bersifat simetris: `P ⊕ K = C`, dan `C ⊕ K = P` lagi — "
            "makanya key yang sama dipakai untuk enkripsi maupun dekripsi."
        )

    tab_encrypt, tab_decrypt = st.tabs(["🔒 Enkripsi", "🔓 Dekripsi"])

    with tab_encrypt:
        _tab_encrypt()

    with tab_decrypt:
        _tab_decrypt()


def _tab_encrypt():
    st.subheader("Enkripsi")

    plaintext = st.text_area("Plaintext", placeholder="Contoh: HELLO", height=100)
    key = st.text_input("Key", placeholder="Contoh: KEY", key="xor_encrypt_key")

    if not st.button("🔒 Enkripsi", type="primary", use_container_width=True):
        return

    if not plaintext.strip():
        st.error("Plaintext tidak boleh kosong.")
        return
    if not key:
        st.error("Key tidak boleh kosong.")
        return

    process = get_xor_process(plaintext, key)

    flow_diagram(ENCRYPT_STAGES)

    st.markdown("#### Tahap 1 — Plaintext → Bytes")
    col1, col2 = st.columns(2)
    col1.markdown("**Plaintext**")
    col1.code(plaintext)
    col2.markdown("**UTF-8 Bytes (HEX)**")
    col2.code(bytes_as_hex(process.plaintext_bytes))

    st.markdown("#### Tahap 2 — Key → Bytes")
    col1, col2 = st.columns(2)
    col1.markdown("**Key asli**")
    col1.code(key)
    col2.markdown("**Key Bytes (HEX)**")
    col2.code(bytes_as_hex(process.key_bytes))

    st.markdown("#### Tahap 3 — Key Diulang (Repeating Key)")
    st.caption(
        "Karena panjang key bisa lebih pendek dari plaintext, "
        "key dipakai berulang secara periodik sampai panjangnya sama."
    )
    st.code(printable_preview(process.repeated_key))
    st.code(bytes_as_hex(process.repeated_key))

    st.markdown("#### Tahap 4 — XOR per Byte")
    st.caption("Setiap byte plaintext di-XOR dengan byte key pada posisi yang sama.")

    st.markdown("**Ringkasan**")
    xor_step_table(process.steps, mode="encrypt")

    with st.expander("Lihat rincian per byte"):
        for step in process.steps:
            st.markdown(f"**Byte {step.index}** — `{step.plaintext_char}` ⊕ `{step.key_char}`")
            xor_step_detail(step, mode="encrypt")
            st.divider()

    st.markdown("#### Tahap 5 — Ciphertext")
    st.success("Enkripsi berhasil.")
    col1, col2 = st.columns(2)
    col1.markdown("**Ciphertext (HEX)** — salin ini untuk didekripsi")
    col1.code(process.ciphertext_hex)
    col2.markdown("**Ciphertext Bytes**")
    col2.code(bytes_as_hex(process.ciphertext))


def _tab_decrypt():
    st.subheader("Dekripsi")

    ciphertext_hex = st.text_area(
        "Ciphertext (HEX)", placeholder="Contoh: 030015070a", height=100
    )
    key = st.text_input("Key", placeholder="Contoh: KEY", key="xor_decrypt_key")

    if not st.button("🔓 Dekripsi", type="primary", use_container_width=True):
        return

    if not ciphertext_hex.strip():
        st.error("Ciphertext HEX tidak boleh kosong.")
        return
    if not key:
        st.error("Key tidak boleh kosong.")
        return

    try:
        ciphertext = bytes.fromhex(ciphertext_hex.strip())
    except ValueError:
        st.error("Ciphertext harus berupa HEX yang valid (contoh: 030015070a).")
        return

    try:
        plaintext = xor_decrypt(ciphertext, key)
    except UnicodeDecodeError:
        st.error("Hasil dekripsi bukan teks UTF-8 yang valid. Pastikan ciphertext dan key benar.")
        return

    steps = get_xor_decryption_process(ciphertext, key)
    key_bytes = key.encode("utf-8")
    repeated_key = bytes(key_bytes[i % len(key_bytes)] for i in range(len(ciphertext)))

    flow_diagram(DECRYPT_STAGES)

    st.markdown("#### Tahap 1 — Ciphertext HEX → Bytes")
    col1, col2 = st.columns(2)
    col1.markdown("**Ciphertext (HEX)**")
    col1.code(ciphertext.hex())
    col2.markdown("**Ciphertext Bytes (biner)**")
    col2.code(bytes_as_binary(ciphertext))

    st.markdown("#### Tahap 2 — Key → Bytes")
    st.code(bytes_as_binary(key_bytes))

    st.markdown("#### Tahap 3 — Key Diulang (Repeating Key)")
    st.caption("Key diulang sepanjang ciphertext, sama seperti pada proses enkripsi.")
    st.code(bytes_as_binary(repeated_key))

    st.markdown("#### Tahap 4 — XOR per Byte")
    st.markdown("**Ringkasan**")
    xor_step_table(steps, mode="decrypt")

    with st.expander("Lihat rincian per byte"):
        for step in steps:
            st.markdown(f"**Byte {step.index}** — Ciphertext ⊕ `{step.key_char}`")
            xor_step_detail(step, mode="decrypt")
            st.divider()

    st.markdown("#### Tahap 5 — Plaintext")
    st.success("Dekripsi berhasil.")
    st.text_area("Plaintext hasil dekripsi", plaintext, height=100, disabled=True)
