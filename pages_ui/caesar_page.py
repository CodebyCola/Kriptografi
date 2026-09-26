"""
Halaman menu: Caesar Cipher (Algoritma Klasik).

"""

import streamlit as st

from ciphers.caesar_cipher import (
    caesar_encrypt,
    caesar_decrypt,
    get_caesar_process,
)
from ui_components import flow_diagram, classic_step_table

ENCRYPT_STAGES = [
    ("1", "Plaintext", "Teks input"),
    ("2", "Geser Huruf", "Tiap huruf digeser maju sejauh shift"),
    ("3", "Ciphertext", "Hasil enkripsi"),
]

DECRYPT_STAGES = [
    ("1", "Ciphertext", "Teks terenkripsi"),
    ("2", "Geser Mundur", "Tiap huruf digeser mundur sejauh shift"),
    ("3", "Plaintext", "Hasil dekripsi"),
]


def render():
    st.title("📜 Caesar Cipher")
    st.caption("Algoritma Kriptografi Klasik — Materi 5")

    st.info("Enkripsi: **C = (P + shift) mod 26**   |   Dekripsi: **P = (C - shift) mod 26**")

    with st.expander("ℹ️ Cara kerja singkat", expanded=False):
        st.markdown(
            "- Setiap huruf pada plaintext digeser maju sejauh `shift` posisi di alfabet.\n"
            "- Huruf besar tetap huruf besar, huruf kecil tetap huruf kecil.\n"
            "- Karakter selain huruf (spasi, angka, tanda baca) **tidak diubah**.\n"
            "- Dekripsi tinggal menggeser mundur sejauh `shift` yang sama — "
            "makanya key (shift) yang sama dipakai untuk enkripsi maupun dekripsi."
        )

    tab_encrypt, tab_decrypt = st.tabs(["🔒 Enkripsi", "🔓 Dekripsi"])

    with tab_encrypt:
        _tab_encrypt()

    with tab_decrypt:
        _tab_decrypt()


def _tab_encrypt():
    st.subheader("Enkripsi")

    plaintext = st.text_area("Plaintext", placeholder="Contoh: HELLO", height=100)
    shift = st.number_input(
        "Pergeseran (shift)", min_value=1, max_value=25, value=3, key="caesar_encrypt_shift"
    )

    if not st.button("🔒 Enkripsi", type="primary", use_container_width=True):
        return

    if not plaintext.strip():
        st.error("Plaintext tidak boleh kosong.")
        return

    hasil = caesar_encrypt(plaintext, shift)
    steps = get_caesar_process(plaintext, shift, mode="encrypt")

    flow_diagram(ENCRYPT_STAGES)

    st.markdown("#### Tahap 1 — Plaintext")
    st.code(plaintext)

    st.markdown(f"#### Tahap 2 — Geser Tiap Huruf Maju {shift} Posisi")
    classic_step_table(steps, input_label="Plaintext", output_label="Ciphertext")

    st.markdown("#### Tahap 3 — Ciphertext")
    st.success("Enkripsi berhasil.")
    st.code(hasil)


def _tab_decrypt():
    st.subheader("Dekripsi")

    ciphertext = st.text_area("Ciphertext", placeholder="Contoh: KHOOR", height=100)
    shift = st.number_input(
        "Pergeseran (shift)", min_value=1, max_value=25, value=3, key="caesar_decrypt_shift"
    )

    if not st.button("🔓 Dekripsi", type="primary", use_container_width=True):
        return

    if not ciphertext.strip():
        st.error("Ciphertext tidak boleh kosong.")
        return

    hasil = caesar_decrypt(ciphertext, shift)
    steps = get_caesar_process(ciphertext, shift, mode="decrypt")

    flow_diagram(DECRYPT_STAGES)

    st.markdown("#### Tahap 1 — Ciphertext")
    st.code(ciphertext)

    st.markdown(f"#### Tahap 2 — Geser Tiap Huruf Mundur {shift} Posisi")
    classic_step_table(steps, input_label="Ciphertext", output_label="Plaintext")

    st.markdown("#### Tahap 3 — Plaintext")
    st.success("Dekripsi berhasil.")
    st.text_area("Plaintext hasil dekripsi", hasil, height=100, disabled=True)
