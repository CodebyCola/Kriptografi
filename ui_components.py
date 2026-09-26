"""
Komponen tampilan yang dipakai bersama oleh semua menu.

Kenapa dipisah di sini?
Supaya kalau menu Caesar/Vigenere/dll juga butuh "tabel step" atau
"kartu alur algoritma", tinggal panggil fungsi ini lagi tanpa copy-paste.
"""

import streamlit as st


def flow_diagram(stages: list[tuple[str, str, str]]):
    """
    Menampilkan alur algoritma sebagai kartu horizontal + panah.

    stages: list of (nomor, judul, deskripsi)
    Dipakai untuk alur enkripsi maupun dekripsi, tinggal beda isi stages-nya.
    """
    cols = st.columns(len(stages))

    for col, (number, title, description) in zip(cols, stages):
        with col:
            with st.container(border=True):
                st.caption(f"STEP {number}")
                st.markdown(f"**{title}**")
                st.caption(description)

    st.markdown(
        "<p style='text-align:center; opacity:0.5; margin:4px 0;'>⬇</p>",
        unsafe_allow_html=True,
    )


def xor_step_table(steps, mode: str = "encrypt"):
    """
    Tabel ringkasan seluruh proses XOR (dipakai untuk enkripsi & dekripsi).

    mode="encrypt" -> kolom kiri "Plaintext", kolom kanan hasil "Ciphertext"
    mode="decrypt" -> kolom kiri "Ciphertext", kolom kanan hasil "Plaintext"
    """
    rows = []

    for step in steps:
        if mode == "encrypt":
            rows.append(
                {
                    "Byte": step.index,
                    "Plaintext": step.plaintext_char,
                    "Biner P": step.plaintext_binary,
                    "Key": step.key_char,
                    "Biner K": step.key_binary,
                    "⊕ Hasil (biner)": step.ciphertext_binary,
                    "Hex": f"{step.ciphertext_byte:02X}",
                }
            )
        else:
            rows.append(
                {
                    "Byte": step.index,
                    "Ciphertext (hex)": f"{step.ciphertext_byte:02X}",
                    "Biner C": step.ciphertext_binary,
                    "Key": step.key_char,
                    "Biner K": step.key_binary,
                    "⊕ Hasil (biner)": step.plaintext_binary,
                    "Plaintext": step.plaintext_char,
                }
            )

    st.dataframe(rows, width="stretch", hide_index=True)


def xor_step_detail(step, mode: str = "encrypt"):
    """
    Rincian 1 baris proses XOR: input | key | hasil, dalam 3 kolom sejajar.
    Satu fungsi ini menggantikan display_encryption_step & display_decryption_step
    yang tadinya dua fungsi terpisah dengan struktur mirip.
    """
    input_label = "Plaintext" if mode == "encrypt" else "Ciphertext"
    result_label = "Ciphertext" if mode == "encrypt" else "Plaintext"

    input_char = step.plaintext_char if mode == "encrypt" else step.ciphertext_char if hasattr(step, "ciphertext_char") else _hex_repr(step)
    input_binary = step.plaintext_binary if mode == "encrypt" else step.ciphertext_binary
    input_decimal = step.plaintext_byte if mode == "encrypt" else step.ciphertext_byte

    result_binary = step.ciphertext_binary if mode == "encrypt" else step.plaintext_binary
    result_decimal = step.ciphertext_byte if mode == "encrypt" else step.plaintext_byte
    result_char = None if mode == "encrypt" else step.plaintext_char

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown(f"**{input_label}**")
        st.code(f"{input_char}\n{input_binary}")
        st.caption(f"Desimal: {input_decimal}")

    with col2:
        st.markdown("**Key**")
        st.code(f"{step.key_char}\n{step.key_binary}")
        st.caption(f"Desimal: {step.key_byte}")

    with col3:
        st.markdown(f"**Hasil ({result_label})**")
        st.code(result_binary)
        if result_char is not None:
            st.caption(f"Karakter: {result_char}")
        else:
            st.caption(f"Desimal: {result_decimal}")

def classic_step_table(steps, input_label: str = "Input", output_label: str = "Hasil", show_key: bool = False):
    """
    Tabel ringkasan proses cipher klasik    
    """
    rows = []

    for step in steps:
        row = {
            "No": step.index + 1,
            input_label: step.original_char,
        }
        if show_key:
            row["Key"] = step.key_char if step.is_alpha else "-"
        row["Geser"] = step.shift_used if step.is_alpha else "-"
        row[output_label] = step.result_char
        rows.append(row)

    st.dataframe(rows, width="stretch", hide_index=True)


def _hex_repr(step) -> str:
    return f"0x{step.ciphertext_byte:02X}"


def bytes_as_hex(data: bytes) -> str:
    return " ".join(f"{b:02X}" for b in data)


def bytes_as_binary(data: bytes) -> str:
    return " ".join(f"{b:08b}" for b in data)


def printable_preview(data: bytes) -> str:
    return " ".join(chr(b) if 32 <= b <= 126 else "·" for b in data)
