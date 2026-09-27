"""Halaman Streamlit untuk Super Enkripsi Caesar -> Vigenere -> Vernam -> ECB."""

import streamlit as st

from ciphers.ecb_cipher import BLOCK_SIZE, KEY_SIZE, generate_random_key
from ciphers.super_encryption import (
    super_decrypt,
    super_encrypt,
    validate_ecb_key,
    validate_hex_key,
)
from ui_components import flow_diagram

ENCRYPT_STAGES = [
    ("1", "Plaintext", "Teks input"),
    ("2", "Caesar", "Geser setiap huruf berdasarkan shift"),
    ("3", "Vigenere", "Geser huruf berdasarkan key berulang"),
    ("4", "Vernam", "XOR byte hasil Vigenere dengan OTP"),
    ("5", "AES-ECB", "Enkripsi hasil Vernam per blok 16 byte"),
    ("6", "Ciphertext", "Hasil akhir dalam HEX"),
]

DECRYPT_STAGES = [
    ("1", "Ciphertext", "Input HEX"),
    ("2", "AES-ECB", "Dekripsi per blok 16 byte"),
    ("3", "Vernam", "XOR kembali dengan OTP"),
    ("4", "Vigenere", "Balik pergeseran berdasarkan key"),
    ("5", "Caesar", "Balik pergeseran berdasarkan shift"),
    ("6", "Plaintext", "Teks asli"),
]


def render():
    st.title("Super Enkripsi")
    st.caption("Gabungan Caesar → Vigenere → Vernam → AES-ECB")

    st.info(
        "**Enkripsi:** Plaintext → Caesar → Vigenere → Vernam → AES-ECB → Ciphertext  \n"
        "**Dekripsi:** Ciphertext → AES-ECB → Vernam → Vigenere → Caesar → Plaintext"
    )

    with st.expander("Cara kerja", expanded=False):
        st.markdown(
            "1. **Caesar** menggeser setiap huruf berdasarkan nilai shift.\n"
            "2. **Vigenere** menggeser hasil Caesar menggunakan key huruf yang diulang.\n"
            "3. **Vernam** mengubah hasil Vigenere menjadi UTF-8 bytes lalu melakukan XOR "
            "dengan key OTP yang panjangnya sama dengan data tersebut.\n"
            "4. **AES-ECB** mengenkripsi hasil XOR menggunakan AES-128 dan PKCS#7 padding.\n\n"
            "Pada dekripsi, seluruh tahapan dibalik urutannya."
        )

    tab_encrypt, tab_decrypt = st.tabs(["Enkripsi", "Dekripsi"])

    with tab_encrypt:
        _tab_encrypt()

    with tab_decrypt:
        _tab_decrypt()


def _generate_ecb_key():
    st.session_state["super_encrypt_ecb_key"] = generate_random_key(KEY_SIZE).hex()


def _tab_encrypt():
    st.subheader("Enkripsi")

    plaintext = st.text_area(
        "Plaintext",
        placeholder="Contoh: HELLO WORLD",
        height=100,
        key="super_plaintext",
    )

    col_caesar, col_vigenere = st.columns(2)
    with col_caesar:
        caesar_shift = st.number_input(
            "Key Caesar (shift)",
            min_value=-100000,
            max_value=100000,
            value=3,
            step=1,
            key="super_caesar_shift",
        )
    with col_vigenere:
        vigenere_key = st.text_input(
            "Key Vigenere",
            placeholder="Contoh: KRIPTO",
            key="super_vigenere_key",
        )

    st.markdown("#### Key Vernam")
    vernam_key_hex = st.text_input(
        "Key Vernam (HEX, opsional)",
        placeholder="Kosongkan untuk generate OTP otomatis",
        key="super_encrypt_vernam_key",
        help=(
            "Panjang key harus sama dengan panjang byte hasil Vigenere. "
            "Key Vernam ditampilkan kembali setelah enkripsi."
        ),
    )

    st.markdown("#### Key AES-ECB")
    st.caption(f"AES-128 membutuhkan key tepat {KEY_SIZE} byte atau 32 karakter HEX.")

    if "super_encrypt_ecb_key" not in st.session_state:
        st.session_state["super_encrypt_ecb_key"] = ""

    col_gen, col_key = st.columns([1, 2])
    with col_gen:
        st.button(
            "Generate Key AES",
            use_container_width=True,
            on_click=_generate_ecb_key,
            key="super_generate_ecb_key",
        )
    with col_key:
        ecb_key_hex = st.text_input(
            "Key AES-ECB (HEX)",
            placeholder="Contoh: 00112233445566778899aabbccddeeff",
            key="super_encrypt_ecb_key",
        )

    if not st.button(
        "Enkripsi", type="primary", use_container_width=True, key="super_encrypt_button"
    ):
        return

    if not plaintext:
        st.error("Plaintext tidak boleh kosong.")
        return

    if not vigenere_key.strip():
        st.error("Key Vigenere tidak boleh kosong.")
        return

    try:
        ecb_key = validate_hex_key(ecb_key_hex, "Key AES-ECB")
        key_error = validate_ecb_key(ecb_key)
        if key_error:
            raise ValueError(key_error)
    except ValueError as exc:
        st.error(str(exc))
        return

    manual_vernam_key = None
    if vernam_key_hex.strip():
        try:
            manual_vernam_key = bytes.fromhex(vernam_key_hex.strip())
        except ValueError:
            st.error("Key Vernam harus berupa HEX yang valid.")
            return

    try:
        result = super_encrypt(
            plaintext=plaintext,
            caesar_shift=int(caesar_shift),
            vigenere_key=vigenere_key,
            vernam_key=manual_vernam_key,
            ecb_key=ecb_key,
        )
    except ValueError as exc:
        st.error(str(exc))
        return

    flow_diagram(ENCRYPT_STAGES)

    st.markdown("#### Tahap 1 — Plaintext")
    st.code(result.plaintext)

    st.markdown("#### Tahap 2 — Caesar")
    st.code(
        f"Shift Caesar : {result.caesar_shift}\n"
        f"Output       : {result.after_caesar}"
    )

    st.markdown("#### Tahap 3 — Vigenere")
    st.code(
        f"Key Vigenere : {result.vigenere_key}\n"
        f"Output       : {result.after_vigenere}"
    )

    st.markdown("#### Tahap 4 — Vernam")
    st.code(
        f"Input UTF-8 HEX : {result.after_vigenere_bytes.hex()}\n"
        f"Vernam key      : {result.vernam_key_hex}\n"
        f"XOR result      : {result.after_vernam_hex}"
    )
    st.caption(
        f"Key Vernam berukuran {len(result.vernam_key)} byte, sama dengan hasil Vigenere "
        "setelah dikonversi ke UTF-8."
    )

    st.markdown("#### Tahap 5 — AES-ECB")
    st.code(
        f"Key AES-128 : {result.ecb_key_hex}\n"
        f"ECB input   : {result.after_vernam_hex}\n"
        f"Ciphertext  : {result.ciphertext_hex}"
    )

    block_rows = []
    for index in range(0, len(result.ciphertext), BLOCK_SIZE):
        block = result.ciphertext[index : index + BLOCK_SIZE]
        block_rows.append(
            {
                "Blok": f"C{index // BLOCK_SIZE + 1}",
                "Ciphertext Block (HEX)": block.hex(),
                "Ukuran": f"{len(block)} byte",
            }
        )
    st.dataframe(block_rows, width="stretch", hide_index=True)

    st.markdown("#### Ciphertext Akhir")
    st.success("Super Enkripsi berhasil.")
    st.code(result.ciphertext_hex)

    with st.expander("Data yang diperlukan untuk dekripsi", expanded=True):
        st.markdown(
            f"- **Key Caesar:** `{result.caesar_shift}`\n"
            f"- **Key Vigenere:** `{result.vigenere_key}`\n"
            f"- **Key Vernam:** `{result.vernam_key_hex}`\n"
            f"- **Key AES-ECB:** `{result.ecb_key_hex}`\n"
            f"- **Ciphertext:** `{result.ciphertext_hex}`"
        )


def _tab_decrypt():
    st.subheader("Dekripsi")

    ciphertext_hex = st.text_area(
        "Ciphertext (HEX)",
        placeholder="Tempel ciphertext hasil Super Enkripsi",
        height=100,
        key="super_decrypt_ciphertext",
    )

    col_caesar, col_vigenere = st.columns(2)
    with col_caesar:
        caesar_shift = st.number_input(
            "Key Caesar (shift)",
            min_value=-100000,
            max_value=100000,
            value=3,
            step=1,
            key="super_decrypt_caesar_shift",
        )
    with col_vigenere:
        vigenere_key = st.text_input(
            "Key Vigenere",
            placeholder="Key yang digunakan saat enkripsi",
            key="super_decrypt_vigenere_key",
        )

    vernam_key_hex = st.text_input(
        "Key Vernam (HEX)",
        placeholder="Key Vernam yang ditampilkan saat enkripsi",
        key="super_decrypt_vernam_key",
    )

    ecb_key_hex = st.text_input(
        "Key AES-ECB (HEX)",
        placeholder="Key AES yang digunakan saat enkripsi",
        key="super_decrypt_ecb_key",
    )

    if not st.button(
        "Dekripsi", type="primary", use_container_width=True, key="super_decrypt_button"
    ):
        return

    if not ciphertext_hex.strip():
        st.error("Ciphertext HEX tidak boleh kosong.")
        return

    try:
        ciphertext = bytes.fromhex(ciphertext_hex.strip())
        vernam_key = validate_hex_key(vernam_key_hex, "Key Vernam")
        ecb_key = validate_hex_key(ecb_key_hex, "Key AES-ECB")
        key_error = validate_ecb_key(ecb_key)
        if key_error:
            raise ValueError(key_error)

        result = super_decrypt(
            ciphertext=ciphertext,
            caesar_shift=int(caesar_shift),
            vigenere_key=vigenere_key,
            vernam_key=vernam_key,
            ecb_key=ecb_key,
        )
    except (ValueError, UnicodeDecodeError) as exc:
        st.error(f"Dekripsi gagal: {exc}")
        return

    flow_diagram(DECRYPT_STAGES)

    st.markdown("#### Tahap 1 — Ciphertext")
    st.code(result.ciphertext.hex())

    st.markdown("#### Tahap 2 — Buka AES-ECB")
    st.code(
        f"Key AES-128 : {result.ecb_key.hex()}\n"
        f"ECB output  : {result.after_ecb_hex}"
    )

    st.markdown("#### Tahap 3 — Buka Vernam")
    st.code(
        f"ECB output  : {result.after_ecb_hex}\n"
        f"Vernam key  : {result.vernam_key.hex()}\n"
        f"XOR result  : {result.after_vernam_hex}"
    )
    st.code(f"Sebagai teks UTF-8: {result.after_vernam_text}")

    st.markdown("#### Tahap 4 — Buka Vigenere")
    st.code(
        f"Key Vigenere : {result.vigenere_key}\n"
        f"Output       : {result.after_vigenere}"
    )

    st.markdown("#### Tahap 5 — Buka Caesar")
    st.code(
        f"Shift Caesar : {result.caesar_shift}\n"
        f"Output       : {result.plaintext}"
    )

    st.markdown("#### Plaintext Hasil Dekripsi")
    st.success("Super Dekripsi berhasil.")
    st.text_area(
        "Plaintext",
        result.plaintext,
        height=100,
        disabled=True,
        key="super_decrypt_result",
    )
