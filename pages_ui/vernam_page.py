"""
Halaman menu: Vernam Cipher / One-Time Pad (Algoritma Modern).

Alur baca kode di file ini:
1. render()          -> dipanggil dari main.py
2. _tab_encrypt()     -> isi tab Enkripsi
3. _tab_decrypt()     -> isi tab Dekripsi
Struktur ditulis semirip mungkin dengan pages_ui/xor_page.py supaya gampang
dibandingkan — bedanya cuma di bagian key (di sini key wajib sepanjang
plaintext, tidak ada "key diulang").
"""

import streamlit as st

from ciphers.vernam_chiper import (
    generate_random_key,
    vernam_decrypt,
    get_vernam_process,
    get_vernam_decryption_process,
)
from ui_components import (
    flow_diagram,
    xor_step_table,
    xor_step_detail,
    bytes_as_hex,
    bytes_as_binary,
)

ENCRYPT_STAGES = [
    ("1", "Plaintext", "Teks input"),
    ("2", "UTF-8", "Konversi ke byte"),
    ("3", "Key Acak", "Key sepanjang plaintext, sekali pakai"),
    ("4", "XOR", "P ⊕ K per byte"),
    ("5", "Ciphertext", "Hasil enkripsi (HEX)"),
]

DECRYPT_STAGES = [
    ("1", "Ciphertext", "Input dalam format HEX"),
    ("2", "Bytes", "HEX → byte"),
    ("3", "Key (OTP)", "Key sepanjang ciphertext, hasil dari proses enkripsi"),
    ("4", "XOR", "C ⊕ K per byte"),
    ("5", "Plaintext", "Hasil dekripsi"),
]


def render():
    st.title("Vernam Cipher (One-Time Pad)")
    st.caption("Algoritma Kriptografi Modern — Materi 5")

    st.info("Enkripsi: **C = P ⊕ K**   |   Dekripsi: **P = C ⊕ K**")

    with st.expander("Cara kerja singkat & bedanya dengan XOR Cipher", expanded=False):
        st.markdown(
            "Operasinya sama persis dengan menu **XOR Cipher**: setiap byte "
            "plaintext di-XOR dengan byte key pada posisi yang sama. "
            "Yang membedakan Vernam Cipher adalah **3 syarat ketat pada key**, "
            "supaya cipher ini punya *perfect secrecy* (Claude Shannon, 1949):\n\n"
            "1. **Sepanjang plaintext** — key **tidak boleh diulang** "
            "(beda dengan menu XOR Cipher, di sana key boleh lebih pendek "
            "lalu diulang).\n"
            "2. **Benar-benar acak** — bukan kata atau kalimat bermakna.\n"
            "3. **Sekali pakai lalu dibuang** — key yang sama tidak boleh "
            "dipakai untuk pesan lain.\n\n"
            "Kalau salah satu syarat dilanggar, secara matematis ini cuma "
            "XOR Cipher dengan key panjang, bukan Vernam Cipher/OTP lagi."
        )

    tab_encrypt, tab_decrypt = st.tabs(["Enkripsi", "Dekripsi"])

    with tab_encrypt:
        _tab_encrypt()

    with tab_decrypt:
        _tab_decrypt()


def _tab_encrypt():
    st.subheader("Enkripsi")

    plaintext = st.text_area(
        "Plaintext", placeholder="Contoh: HELLO", height=100, key="vernam_plaintext"
    )

    st.caption(
        "Key one-time pad wajib sepanjang plaintext (dalam byte UTF-8). "
        "Paling gampang, generate saja key acaknya di bawah ini."
    )

    plaintext_length = len(plaintext.encode("utf-8")) if plaintext else 0

    col_gen, col_info = st.columns([1, 2])
    with col_gen:
        generate = st.button(
            "Generate Key Acak",
            use_container_width=True,
            disabled=plaintext_length == 0,
        )
    with col_info:
        if plaintext_length:
            st.caption(f"Panjang plaintext saat ini: **{plaintext_length} byte** → key harus {plaintext_length} byte.")

    if generate and plaintext_length:
        st.session_state["vernam_encrypt_key"] = generate_random_key(plaintext_length).hex()

    key_hex = st.text_input(
        "Key (HEX)",
        placeholder="Klik 'Generate Key Acak' atau isi manual dalam format HEX",
        key="vernam_encrypt_key",
        help="Panjang key HEX harus 2x panjang plaintext dalam byte (1 byte = 2 karakter HEX).",
    )

    if not st.button("Enkripsi", type="primary", use_container_width=True):
        return

    if not plaintext.strip():
        st.error("Plaintext tidak boleh kosong.")
        return
    if not key_hex.strip():
        st.error("Key tidak boleh kosong. Klik 'Generate Key Acak' atau isi manual.")
        return

    try:
        key = bytes.fromhex(key_hex.strip())
    except ValueError:
        st.error("Key harus berupa HEX yang valid (contoh: 1a2b3c...).")
        return

    try:
        process = get_vernam_process(plaintext, key)
    except ValueError as e:
        st.error(str(e))
        return

    flow_diagram(ENCRYPT_STAGES)

    st.markdown("#### Tahap 1 — Plaintext → Bytes")
    col1, col2 = st.columns(2)
    col1.markdown("**Plaintext**")
    col1.code(plaintext)
    col2.markdown("**UTF-8 Bytes (HEX)**")
    col2.code(bytes_as_hex(process.plaintext_bytes))

    st.markdown("#### Tahap 2 — Key (One-Time Pad)")
    st.caption(
        "Key ini panjangnya sama persis dengan plaintext dan tidak diulang. "
        "Simpan key ini kalau mau dekripsi ciphertext di bawah nanti — lalu "
        "buang/jangan pakai lagi untuk pesan lain."
    )
    st.code(process.key_hex)

    st.markdown("#### Tahap 3 — XOR per Byte")
    st.caption("Setiap byte plaintext di-XOR dengan byte key pada posisi yang sama.")

    st.markdown("**Ringkasan**")
    xor_step_table(process.steps, mode="encrypt")

    with st.expander("Lihat rincian per byte"):
        for step in process.steps:
            st.markdown(f"**Byte {step.index}** — `{step.plaintext_char}` ⊕ `{step.key_char}`")
            xor_step_detail(step, mode="encrypt")
            st.divider()

    st.markdown("#### Tahap 4 — Ciphertext")
    st.success("Enkripsi berhasil.")
    col1, col2 = st.columns(2)
    col1.markdown("**Ciphertext (HEX)** — salin ini untuk didekripsi")
    col1.code(process.ciphertext_hex)
    col2.markdown("**Key (HEX)** — wajib disimpan, sekali pakai")
    col2.code(process.key_hex)


def _tab_decrypt():
    st.subheader("Dekripsi")

    ciphertext_hex = st.text_area(
        "Ciphertext (HEX)", placeholder="Contoh: 030015070a", height=100
    )
    key_hex = st.text_input(
        "Key (HEX)",
        placeholder="Key OTP yang sama dengan yang dipakai saat enkripsi",
        key="vernam_decrypt_key",
    )

    if not st.button("Dekripsi", type="primary", use_container_width=True):
        return

    if not ciphertext_hex.strip():
        st.error("Ciphertext HEX tidak boleh kosong.")
        return
    if not key_hex.strip():
        st.error("Key tidak boleh kosong.")
        return

    try:
        ciphertext = bytes.fromhex(ciphertext_hex.strip())
    except ValueError:
        st.error("Ciphertext harus berupa HEX yang valid (contoh: 030015070a).")
        return

    try:
        key = bytes.fromhex(key_hex.strip())
    except ValueError:
        st.error("Key harus berupa HEX yang valid (contoh: 1a2b3c...).")
        return

    if len(key) != len(ciphertext):
        st.error(
            f"Panjang key ({len(key)} byte) harus sama persis dengan "
            f"panjang ciphertext ({len(ciphertext)} byte) pada Vernam Cipher."
        )
        return

    try:
        plaintext = vernam_decrypt(ciphertext, key)
    except UnicodeDecodeError:
        st.error("Hasil dekripsi bukan teks UTF-8 yang valid. Pastikan ciphertext dan key benar.")
        return

    steps = get_vernam_decryption_process(ciphertext, key)

    flow_diagram(DECRYPT_STAGES)

    st.markdown("#### Tahap 1 — Ciphertext HEX → Bytes")
    col1, col2 = st.columns(2)
    col1.markdown("**Ciphertext (HEX)**")
    col1.code(ciphertext.hex())
    col2.markdown("**Ciphertext Bytes (biner)**")
    col2.code(bytes_as_binary(ciphertext))

    st.markdown("#### Tahap 2 — Key (One-Time Pad)")
    st.caption("Key ini harus sama persis dengan key yang dipakai saat enkripsi.")
    st.code(bytes_as_binary(key))

    st.markdown("#### Tahap 3 — XOR per Byte")
    st.markdown("**Ringkasan**")
    xor_step_table(steps, mode="decrypt")

    with st.expander("Lihat rincian per byte"):
        for step in steps:
            st.markdown(f"**Byte {step.index}** — Ciphertext ⊕ `{step.key_char}`")
            xor_step_detail(step, mode="decrypt")
            st.divider()

    st.markdown("#### Tahap 4 — Plaintext")
    st.success("Dekripsi berhasil.")
    st.text_area("Plaintext hasil dekripsi", plaintext, height=100, disabled=True)