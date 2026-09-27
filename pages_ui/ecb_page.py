"""
Halaman menu: ECB — Electronic Codebook (Algoritma Modern, mode operasi block cipher).

Alur baca kode di file ini:
1. render()          -> dipanggil dari main.py
2. _tab_encrypt()     -> isi tab Enkripsi
3. _tab_decrypt()     -> isi tab Dekripsi
Struktur ditulis semirip mungkin dengan pages_ui/vernam_page.py supaya gampang
dibandingkan — bedanya di sini kerjanya per BLOK 16 byte (AES), bukan per byte.
"""

import streamlit as st

from ciphers.ecb_cipher import (
    BLOCK_SIZE,
    KEY_SIZE,
    generate_random_key,
    ecb_decrypt,
    get_ecb_process,
    get_ecb_decryption_process,
)
from ui_components import flow_diagram, bytes_as_hex

ENCRYPT_STAGES = [
    ("1", "Plaintext", "Teks input"),
    ("2", "UTF-8", "Konversi ke byte"),
    ("3", "Padding", "PKCS#7, genapkan ke kelipatan 16 byte"),
    ("4", "Split Blok", "Potong jadi blok 16 byte"),
    ("5", "AES per Blok", "Tiap blok dienkripsi sendiri-sendiri, key sama"),
    ("6", "Ciphertext", "Gabungan semua blok (HEX)"),
]

DECRYPT_STAGES = [
    ("1", "Ciphertext", "Input dalam format HEX"),
    ("2", "Split Blok", "Potong jadi blok 16 byte"),
    ("3", "AES per Blok", "Tiap blok didekripsi sendiri-sendiri, key sama"),
    ("4", "Gabung Blok", "Satukan hasil semua blok"),
    ("5", "Unpad", "Buang padding PKCS#7"),
    ("6", "Plaintext", "Hasil dekripsi"),
]


def render():
    st.title("ECB (Electronic Codebook)")
    st.caption("Algoritma Kriptografi Modern — Materi 5")

    st.info(
        "ECB itu **mode operasi** block cipher (di sini blok ciphernya AES-128). "
        "Plaintext dipotong jadi blok 16 byte, lalu **tiap blok dienkripsi sendiri-sendiri** "
        "dengan key yang sama — tidak ada hubungan antar blok."
    )

    with st.expander("Cara kerja singkat & kenapa ECB dianggap lemah", expanded=False):
        st.markdown(
            "**Langkah ECB:**\n\n"
            "1. Plaintext dipotong jadi blok berukuran tetap (AES = 16 byte/blok).\n"
            "2. Blok terakhir di-*pad* (PKCS#7) supaya genap 16 byte.\n"
            "3. Setiap blok dienkripsi **independen** pakai key yang sama — "
            "beda dengan mode CBC/CTR yang menyambungkan blok satu ke blok "
            "berikutnya lewat IV/chaining.\n"
            "4. Ciphertext akhir = gabungan seluruh blok yang sudah dienkripsi.\n\n"
            "**Kelemahannya:** karena tiap blok independen, **blok plaintext yang "
            "sama akan selalu menghasilkan blok ciphertext yang sama** (selama key-nya "
            "sama). Kalau plaintext-nya punya banyak bagian berulang, pola itu masih "
            "bisa terlihat di ciphertext — walaupun isinya sudah terenkripsi. Di tabel "
            "hasil enkripsi bawah, blok yang punya pasangan kembar akan ditandai."
        )

    tab_encrypt, tab_decrypt = st.tabs(["Enkripsi", "Dekripsi"])

    with tab_encrypt:
        _tab_encrypt()

    with tab_decrypt:
        _tab_decrypt()


def _tab_encrypt():
    st.subheader("Enkripsi")

    plaintext = st.text_area(
        "Plaintext",
        placeholder="Contoh: HELLOHELLOHELLO! (coba isi teks berulang untuk lihat kelemahan ECB)",
        height=100,
        key="ecb_plaintext",
    )

    st.caption(f"Key AES-128 wajib {KEY_SIZE} byte. Paling gampang, generate saja key acaknya di bawah ini.")

    col_gen, col_info = st.columns([1, 2])
    with col_gen:
        generate = st.button("Generate Key Acak", use_container_width=True)
    with col_info:
        st.caption(f"Blok AES = {BLOCK_SIZE} byte. Panjang plaintext akan otomatis di-*pad* sampai kelipatan {BLOCK_SIZE} byte.")

    if generate:
        st.session_state["ecb_generated_key_hex"] = generate_random_key(KEY_SIZE).hex()

    key_hex = st.text_input(
        "Key (HEX)",
        value=st.session_state.get("ecb_generated_key_hex", ""),
        placeholder="Klik 'Generate Key Acak' atau isi manual dalam format HEX",
        key="ecb_encrypt_key",
        help=f"Panjang key HEX harus {KEY_SIZE * 2} karakter ({KEY_SIZE} byte = AES-128).",
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
        process = get_ecb_process(plaintext, key)
    except ValueError as e:
        st.error(str(e))
        return

    flow_diagram(ENCRYPT_STAGES)

    st.markdown("#### Tahap 1 — Plaintext → Bytes → Padding")
    col1, col2 = st.columns(2)
    col1.markdown("**Plaintext**")
    col1.code(plaintext)
    col2.markdown("**UTF-8 Bytes (HEX)**")
    col2.code(bytes_as_hex(process.plaintext_bytes))

    st.caption(
        f"Panjang asli: **{len(process.plaintext_bytes)} byte** → ditambah "
        f"**{process.padding_length} byte padding** (PKCS#7) → total "
        f"**{len(process.padded_bytes)} byte** ({len(process.blocks)} blok)."
    )
    st.code(bytes_as_hex(process.padded_bytes))

    st.markdown("#### Tahap 2 — Key AES-128")
    st.caption("Key ini dipakai sama persis untuk mengenkripsi SETIAP blok.")
    st.code(process.key_hex)

    st.markdown("#### Tahap 3 — Enkripsi per Blok")
    st.caption("Setiap blok 16 byte dienkripsi sendiri-sendiri dengan key yang sama.")

    _render_block_table(process.blocks, mode="encrypt")

    duplicates = [b for b in process.blocks if b.duplicate_of_index is not None]
    if duplicates:
        contoh = duplicates[0]
        st.warning(
            f"Blok #{contoh.index} punya plaintext yang sama dengan blok #{contoh.duplicate_of_index} — "
            "lihat kolom **Ciphertext (HEX)**, hasilnya juga identik. Inilah kelemahan khas mode ECB."
        )

    with st.expander("Lihat rincian per blok"):
        for step in process.blocks:
            label = " (blok padding)" if step.is_padding_block else ""
            st.markdown(f"**Blok {step.index}{label}**")
            col1, col2 = st.columns(2)
            col1.markdown("Plaintext (HEX)")
            col1.code(step.plaintext_block_hex)
            col2.markdown("Ciphertext (HEX)")
            col2.code(step.ciphertext_block_hex)
            st.divider()

    st.markdown("#### Tahap 4 — Ciphertext")
    st.success("Enkripsi berhasil.")
    col1, col2 = st.columns(2)
    col1.markdown("**Ciphertext (HEX)** — salin ini untuk didekripsi")
    col1.code(process.ciphertext_hex)
    col2.markdown("**Key (HEX)** — wajib disimpan untuk dekripsi")
    col2.code(process.key_hex)


def _tab_decrypt():
    st.subheader("Dekripsi")

    ciphertext_hex = st.text_area(
        "Ciphertext (HEX)",
        placeholder="Tempel ciphertext HEX hasil enkripsi ECB",
        height=100,
    )
    key_hex = st.text_input(
        "Key (HEX)",
        placeholder="Key AES yang sama dengan yang dipakai saat enkripsi",
        key="ecb_decrypt_key",
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
        st.error("Ciphertext harus berupa HEX yang valid.")
        return

    try:
        key = bytes.fromhex(key_hex.strip())
    except ValueError:
        st.error("Key harus berupa HEX yang valid.")
        return

    try:
        steps = get_ecb_decryption_process(ciphertext, key)
    except ValueError as e:
        st.error(str(e))
        return

    try:
        plaintext = ecb_decrypt(ciphertext, key)
    except ValueError as e:
        st.error(str(e))
        return
    except UnicodeDecodeError:
        st.error("Hasil dekripsi bukan teks UTF-8 yang valid. Pastikan ciphertext dan key benar.")
        return

    flow_diagram(DECRYPT_STAGES)

    st.markdown("#### Tahap 1 — Ciphertext HEX → Blok")
    st.code(bytes_as_hex(ciphertext))
    st.caption(f"Total {len(ciphertext)} byte = {len(steps)} blok (@{BLOCK_SIZE} byte).")

    st.markdown("#### Tahap 2 — Key AES-128")
    st.caption("Key ini harus sama persis dengan key yang dipakai saat enkripsi.")
    st.code(key.hex())

    st.markdown("#### Tahap 3 — Dekripsi per Blok")
    _render_block_table(steps, mode="decrypt")

    with st.expander("Lihat rincian per blok"):
        for step in steps:
            st.markdown(f"**Blok {step.index}**")
            col1, col2 = st.columns(2)
            col1.markdown("Ciphertext (HEX)")
            col1.code(step.ciphertext_block_hex)
            col2.markdown("Plaintext (HEX)")
            col2.code(step.plaintext_block_hex)
            st.divider()

    st.markdown("#### Tahap 4 — Unpad → Plaintext")
    st.success("Dekripsi berhasil.")
    st.text_area("Plaintext hasil dekripsi", plaintext, height=100, disabled=True)


def _render_block_table(blocks, mode: str = "encrypt"):
    rows = []
    for step in blocks:
        status = "duplikat!" if step.duplicate_of_index is not None else "-"
        row = {
            "Blok": step.index,
            "Plaintext (HEX)": step.plaintext_block_hex,
            "Ciphertext (HEX)": step.ciphertext_block_hex,
            "Padding?": "ya" if step.is_padding_block else "-",
        }
        if mode == "encrypt":
            row["Blok Sama Dengan"] = status if step.duplicate_of_index is None else f"blok #{step.duplicate_of_index} ⚠️"
        rows.append(row)

    st.dataframe(rows, width="stretch", hide_index=True)