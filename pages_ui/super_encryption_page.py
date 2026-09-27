"""
Halaman menu: Super Enkripsi (gabungan 4 algoritma).

Alur baca kode di file ini:
1. render()         -> dipanggil dari main.py
2. _tab_encrypt()    -> isi tab Enkripsi
3. _tab_decrypt()    -> isi tab Dekripsi
Struktur ditulis semirip mungkin dengan pages_ui/vernam_page.py dan
pages_ui/xor_page.py supaya gampang dibandingkan.

File ini HANYA mengurus tampilan. Semua logic penggabungan 4 algoritma
ada di ciphers/super_encryption.py (lihat docstring di file itu untuk
penjelasan lengkap kenapa urutannya Caesar -> Vigenere -> XOR -> Vernam).
"""

import streamlit as st

from ciphers.super_encryption import (
    validate_super_keys,
    super_encrypt,
    super_decrypt,
)
from ui_components import flow_diagram, bytes_as_hex

ENCRYPT_STAGES = [
    ("1", "Plaintext", "Teks input"),
    ("2", "Caesar", "Geser tiap huruf sejauh shift"),
    ("3", "Vigenere", "Geser huruf, kunci berulang"),
    ("4", "XOR", "XOR byte, kunci berulang"),
    ("5", "Vernam", "XOR byte, kunci acak (OTP)"),
]

DECRYPT_STAGES = [
    ("1", "Ciphertext", "Input dalam format HEX"),
    ("2", "Vernam", "Buka XOR dengan key OTP"),
    ("3", "XOR", "Buka XOR dengan key berulang"),
    ("4", "Vigenere", "Geser balik huruf, kunci berulang"),
    ("5", "Caesar", "Geser balik huruf, hasil Plaintext"),
]


def render():
    st.title("Super Enkripsi")
    st.caption("Gabungan 4 Algoritma — Caesar → Vigenère → XOR → Vernam")

    st.info(
        "**Enkripsi:** Plaintext → Caesar → Vigenère → XOR → Vernam → Ciphertext  \n"
        "**Dekripsi:** kebalikannya — Vernam → XOR → Vigenère → Caesar → Plaintext"
    )

    with st.expander("Cara kerja & kenapa urutannya begini", expanded=False):
        st.markdown(
            "- **Caesar** dan **Vigenère** adalah cipher substitusi huruf: "
            "keduanya bekerja di atas teks (huruf A-Z/a-z) dan meneruskan "
            "karakter lain (spasi, angka, tanda baca) apa adanya. Karena "
            "sama-sama menerima & menghasilkan teks, keduanya dirangkai "
            "duluan, saling menyambung langsung.\n"
            "- **XOR** dan **Vernam** bekerja di level byte, bukan huruf. "
            "Begitu masuk XOR, hasil Vigenère (teks) diubah ke byte (UTF-8), "
            "lalu setiap byte-nya di-XOR hasilnya sudah bukan huruf yang "
            "bisa dibaca lagi. Karena itu keduanya ditaruh paling akhir.\n"
            "- **Vernam** butuh key acak yang panjangnya **persis sama** "
            "dengan data pada tahap itu (syarat *one-time pad*). Karena "
            "panjang itu baru pasti setelah tahap XOR selesai, key Vernam "
            "**di-generate otomatis** saat tombol Enkripsi ditekan.\n"
            "- Dekripsi membalik urutan: yang terakhir dienkripsi (Vernam), "
            "dibongkar duluan. Semua key (Caesar, Vigenère, XOR, **dan** key "
            "Vernam hasil generate) wajib disimpan — tanpa salah satunya, "
            "ciphertext tidak akan bisa kembali jadi plaintext."
        )

    tab_encrypt, tab_decrypt = st.tabs(["🔒 Enkripsi", "🔓 Dekripsi"])

    with tab_encrypt:
        _tab_encrypt()

    with tab_decrypt:
        _tab_decrypt()


# ============================================================
# Tab Enkripsi
# ============================================================

def _tab_encrypt():
    st.subheader("Enkripsi")

    plaintext = st.text_area(
        "Plaintext", placeholder="Contoh: HELLO WORLD", height=100, key="super_plaintext"
    )

    col1, col2, col3 = st.columns(3)
    with col1:
        caesar_shift = st.number_input(
            "Shift Caesar", min_value=1, max_value=25, value=3, key="super_encrypt_caesar_shift"
        )
    with col2:
        vigenere_key = st.text_input(
            "Kunci Vigenère", placeholder="Contoh: KEY", key="super_encrypt_vigenere_key"
        )
    with col3:
        xor_key = st.text_input(
            "Kunci XOR", placeholder="Contoh: SECRET", key="super_encrypt_xor_key"
        )

    st.caption(
        "Kunci Vernam (OTP) **tidak perlu diisi** — akan digenerate otomatis "
        "secara acak sepanjang data pada tahap itu, sesuai syarat one-time pad."
    )

    if not st.button("🔒 Enkripsi", type="primary", use_container_width=True, key="super_encrypt_button"):
        return

    if not plaintext.strip():
        st.error("Plaintext tidak boleh kosong.")
        return

    error = validate_super_keys(vigenere_key, xor_key)
    if error:
        st.error(error)
        return

    result = super_encrypt(
        plaintext=plaintext,
        caesar_shift=caesar_shift,
        vigenere_key=vigenere_key,
        xor_key=xor_key,
    )

    flow_diagram(ENCRYPT_STAGES)

    st.markdown("#### Tahap 1 — Plaintext")
    st.code(result.plaintext)

    st.markdown(f"#### Tahap 2 — Caesar Cipher (shift {result.caesar_shift})")
    st.code(result.after_caesar)

    st.markdown(f"#### Tahap 3 — Vigenère Cipher (kunci `{result.vigenere_key.upper()}`)")
    st.code(result.after_vigenere)

    st.markdown(f"#### Tahap 4 — XOR Cipher (kunci `{result.xor_key}`)")
    st.caption("Mulai tahap ini data berupa byte, ditampilkan dalam format HEX.")
    st.code(result.after_xor_hex)

    st.markdown("#### Tahap 5 — Vernam Cipher (kunci acak / one-time pad)")
    st.warning(
        "⚠️ **Simpan key Vernam ini!** Key ini digenerate otomatis dan "
        "**wajib** dipakai lagi saat dekripsi tanpanya ciphertext tidak "
        "bisa dibalik ke plaintext."
    )
    st.code(result.vernam_key_hex)

    st.markdown("#### 🔐 Ciphertext Akhir")
    st.success("Super Enkripsi berhasil.")
    st.code(result.ciphertext_hex)

    with st.expander("📋 Ringkasan semua kunci (salin untuk dekripsi)", expanded=True):
        st.markdown(
            f"- **Shift Caesar:** `{result.caesar_shift}`\n"
            f"- **Kunci Vigenère:** `{result.vigenere_key.upper()}`\n"
            f"- **Kunci XOR:** `{result.xor_key}`\n"
            f"- **Kunci Vernam (HEX):** `{result.vernam_key_hex}`\n"
            f"- **Ciphertext (HEX):** `{result.ciphertext_hex}`"
        )


# ============================================================
# Tab Dekripsi
# ============================================================

def _tab_decrypt():
    st.subheader("Dekripsi")

    ciphertext_hex = st.text_area(
        "Ciphertext (HEX)", placeholder="Contoh: 4f1a3c...", height=100, key="super_decrypt_ciphertext"
    )

    col1, col2, col3 = st.columns(3)
    with col1:
        caesar_shift = st.number_input(
            "Shift Caesar", min_value=1, max_value=25, value=3, key="super_decrypt_caesar_shift"
        )
    with col2:
        vigenere_key = st.text_input(
            "Kunci Vigenère", placeholder="Contoh: KEY", key="super_decrypt_vigenere_key"
        )
    with col3:
        xor_key = st.text_input(
            "Kunci XOR", placeholder="Contoh: SECRET", key="super_decrypt_xor_key"
        )

    vernam_key_hex = st.text_input(
        "Kunci Vernam / OTP (HEX)",
        placeholder="Key yang ditampilkan saat proses Enkripsi",
        key="super_decrypt_vernam_key",
    )

    if not st.button("🔓 Dekripsi", type="primary", use_container_width=True, key="super_decrypt_button"):
        return

    if not ciphertext_hex.strip():
        st.error("Ciphertext HEX tidak boleh kosong.")
        return

    error = validate_super_keys(vigenere_key, xor_key)
    if error:
        st.error(error)
        return

    if not vernam_key_hex.strip():
        st.error("Kunci Vernam (OTP) tidak boleh kosong.")
        return

    try:
        ciphertext = bytes.fromhex(ciphertext_hex.strip())
    except ValueError:
        st.error("Ciphertext harus berupa HEX yang valid (contoh: 4f1a3c...).")
        return

    try:
        vernam_key = bytes.fromhex(vernam_key_hex.strip())
    except ValueError:
        st.error("Kunci Vernam harus berupa HEX yang valid (contoh: 1a2b3c...).")
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
            xor_key=xor_key,
            vernam_key=vernam_key,
        )
    except UnicodeDecodeError:
        st.error(
            "Hasil dekripsi bukan teks UTF-8 yang valid. Pastikan ciphertext "
            "dan semua kunci (Caesar, Vigenère, XOR, Vernam) benar."
        )
        return
    except ValueError as e:
        st.error(str(e))
        return

    flow_diagram(DECRYPT_STAGES)

    st.markdown("#### Tahap 1 — Ciphertext")
    st.code(result.ciphertext.hex())

    st.markdown("#### Tahap 2 — Buka Vernam Cipher (⊕ kunci OTP)")
    st.caption("Masih berupa byte, ditampilkan dalam format HEX.")
    st.code(result.after_vernam_hex)

    st.markdown(f"#### Tahap 3 — Buka XOR Cipher (⊕ kunci `{result.xor_key}`)")
    st.caption("Hasil tahap ini sudah kembali jadi teks (str).")
    st.code(result.after_xor)

    st.markdown(f"#### Tahap 4 — Buka Vigenère Cipher (kunci `{result.vigenere_key.upper()}`)")
    st.code(result.after_vigenere)

    st.markdown(f"#### Tahap 5 — Buka Caesar Cipher (shift {result.caesar_shift})")
    st.success("Super Dekripsi berhasil.")
    st.text_area(
        "Plaintext hasil dekripsi",
        result.plaintext,
        height=100,
        disabled=True,
        key="super_decrypt_result",
    )
