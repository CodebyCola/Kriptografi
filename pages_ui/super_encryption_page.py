"""Halaman Streamlit untuk pipeline Super Enkripsi."""

import streamlit as st

from ciphers.super_encryption import (
    validate_super_keys,
    super_encrypt,
    super_decrypt,
)
from ui_components import flow_diagram

ENCRYPT_STAGES = [
    ("1", "Plaintext", "Teks input"),
    ("2", "Caesar", "Geser tiap huruf sejauh shift"),
    ("3", "Vigenere", "Geser huruf, kunci berulang"),
    ("4", "Vernam", "XOR byte dengan key OTP"),
    ("5", "Ciphertext", "Hasil enkripsi (HEX)"),
]

DECRYPT_STAGES = [
    ("1", "Ciphertext", "Input dalam format HEX"),
    ("2", "Vernam", "Buka XOR byte dengan key OTP"),
    ("3", "Vigenere", "Geser balik huruf, kunci berulang"),
    ("4", "Caesar", "Geser balik huruf"),
    ("5", "Plaintext", "Hasil dekripsi"),
]


def render():
    st.title("Super Enkripsi")
    st.caption("Gabungan 3 Algoritma — Caesar → Vigenère → Vernam")

    st.info(
        "**Enkripsi:** Plaintext → Caesar → Vigenère → Vernam → Ciphertext  \n"
        "**Dekripsi:** kebalikannya — Vernam → Vigenère → Caesar → Plaintext"
    )

    with st.expander("Cara kerja & kenapa urutannya begini", expanded=False):
        st.markdown(
            "- **Caesar** dan **Vigenère** bekerja pada teks sehingga keduanya "
            "dapat dirangkai langsung.\n"
            "- **Vernam** bekerja pada byte UTF-8 dan membutuhkan key dengan "
            "panjang yang persis sama dengan data. Karena panjang data baru "
            "pasti setelah Vigenère selesai, key OTP dibuat setelah tahap itu.\n"
            "- Dekripsi selalu membalik urutan enkripsi. Key Vernam yang tampil "
            "saat enkripsi harus disimpan untuk proses dekripsi."
        )

    tab_encrypt, tab_decrypt = st.tabs(["Enkripsi", "Dekripsi"])

    with tab_encrypt:
        _tab_encrypt()

    with tab_decrypt:
        _tab_decrypt()


def _tab_encrypt():
    st.subheader("Enkripsi")

    plaintext = st.text_area(
        "Plaintext", placeholder="Contoh: HELLO WORLD", height=100, key="super_plaintext"
    )

    col1, col2 = st.columns(2)
    with col1:
        caesar_shift = st.number_input(
            "Shift Caesar", min_value=1, max_value=25, value=3, key="super_encrypt_caesar_shift"
        )
    with col2:
        vigenere_key = st.text_input(
            "Kunci Vigenère", placeholder="Contoh: KEY", key="super_encrypt_vigenere_key"
        )

    st.caption(
        "Kunci Vernam (OTP) tidak perlu diisi — akan digenerate otomatis "
        "sepanjang hasil Vigenère dalam byte UTF-8."
    )

    if not st.button(
        "Enkripsi", type="primary", use_container_width=True, key="super_encrypt_button"
    ):
        return

    if not plaintext.strip():
        st.error("Plaintext tidak boleh kosong.")
        return

    error = validate_super_keys(vigenere_key)
    if error:
        st.error(error)
        return

    result = super_encrypt(
        plaintext=plaintext,
        caesar_shift=caesar_shift,
        vigenere_key=vigenere_key,
    )

    flow_diagram(ENCRYPT_STAGES)

    st.markdown("#### Tahap 1 — Plaintext")
    st.code(result.plaintext)

    st.markdown(f"#### Tahap 2 — Caesar Cipher (shift {result.caesar_shift})")
    st.code(result.after_caesar)

    st.markdown(f"#### Tahap 3 — Vigenère Cipher (kunci `{result.vigenere_key.upper()}`)")
    st.code(result.after_vigenere)

    st.markdown("#### Tahap 4 — Vernam Cipher (key OTP)")
    st.warning(
        "Simpan key Vernam ini. Key tersebut wajib digunakan lagi saat dekripsi."
    )
    st.code(result.vernam_key_hex)

    st.markdown("#### Ciphertext Akhir")
    st.success("Super Enkripsi berhasil.")
    st.code(result.ciphertext_hex)

    with st.expander("Ringkasan untuk dekripsi", expanded=True):
        st.markdown(
            f"- **Shift Caesar:** `{result.caesar_shift}`\n"
            f"- **Kunci Vigenère:** `{result.vigenere_key.upper()}`\n"
            f"- **Kunci Vernam (HEX):** `{result.vernam_key_hex}`\n"
            f"- **Ciphertext (HEX):** `{result.ciphertext_hex}`"
        )


def _tab_decrypt():
    st.subheader("Dekripsi")

    ciphertext_hex = st.text_area(
        "Ciphertext (HEX)", placeholder="Contoh: 4f1a3c...", height=100,
        key="super_decrypt_ciphertext"
    )

    col1, col2 = st.columns(2)
    with col1:
        caesar_shift = st.number_input(
            "Shift Caesar", min_value=1, max_value=25, value=3, key="super_decrypt_caesar_shift"
        )
    with col2:
        vigenere_key = st.text_input(
            "Kunci Vigenère", placeholder="Contoh: KEY", key="super_decrypt_vigenere_key"
        )

    vernam_key_hex = st.text_input(
        "Kunci Vernam / OTP (HEX)",
        placeholder="Key yang ditampilkan saat proses Enkripsi",
        key="super_decrypt_vernam_key",
    )

    if not st.button(
        "Dekripsi", type="primary", use_container_width=True, key="super_decrypt_button"
    ):
        return

    if not ciphertext_hex.strip():
        st.error("Ciphertext HEX tidak boleh kosong.")
        return

    error = validate_super_keys(vigenere_key)
    if error:
        st.error(error)
        return

    if not vernam_key_hex.strip():
        st.error("Kunci Vernam (OTP) tidak boleh kosong.")
        return

    try:
        ciphertext = bytes.fromhex(ciphertext_hex.strip())
        vernam_key = bytes.fromhex(vernam_key_hex.strip())
    except ValueError:
        st.error("Ciphertext dan kunci Vernam harus berupa HEX yang valid.")
        return

    if len(vernam_key) != len(ciphertext):
        st.error(
            f"Panjang kunci Vernam ({len(vernam_key)} byte) harus sama persis "
            f"dengan panjang ciphertext ({len(ciphertext)} byte)."
        )
        return

    try:
        result = super_decrypt(
            ciphertext=ciphertext,
            caesar_shift=caesar_shift,
            vigenere_key=vigenere_key,
            vernam_key=vernam_key,
        )
    except UnicodeDecodeError:
        st.error(
            "Hasil pembukaan Vernam bukan teks UTF-8 yang valid. Pastikan "
            "ciphertext dan semua kunci benar."
        )
        return
    except ValueError as e:
        st.error(str(e))
        return

    flow_diagram(DECRYPT_STAGES)

    st.markdown("#### Tahap 1 — Ciphertext")
    st.code(result.ciphertext.hex())

    st.markdown("#### Tahap 2 — Buka Vernam Cipher")
    st.code(result.after_vernam)

    st.markdown(f"#### Tahap 3 — Buka Vigenère Cipher (kunci `{result.vigenere_key.upper()}`)")
    st.code(result.after_vigenere)

    st.markdown(f"#### Tahap 4 — Buka Caesar Cipher (shift {result.caesar_shift})")
    st.code(result.after_caesar)

    st.success("Super Dekripsi berhasil.")
    st.text_area(
        "Plaintext hasil dekripsi",
        result.plaintext,
        height=100,
        disabled=True,
        key="super_decrypt_result",
    )
