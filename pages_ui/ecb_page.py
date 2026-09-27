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
    ("0", "Key AES-128", "Generate / input key 16 byte"),
    ("1", "Plaintext", "Teks asli yang akan dienkripsi"),
    ("2", "UTF-8", "Teks dikonversi menjadi bytes"),
    ("3", "PKCS#7 Padding", "Tambahkan padding sampai kelipatan 16 byte"),
    ("4", "Split Blok", "Padded bytes dibagi menjadi blok 16 byte"),
    ("5", "AES-ECB", "Setiap blok dienkripsi independen dengan key yang sama"),
    ("6", "Gabung", "Semua ciphertext block digabung"),
    ("7", "Ciphertext HEX", "Hasil akhir ditampilkan dalam HEX"),
]

DECRYPT_STAGES = [
    ("1", "Ciphertext HEX", "HEX diubah kembali menjadi bytes"),
    ("2", "Split Blok", "Ciphertext dibagi menjadi blok 16 byte"),
    ("3", "AES-ECB", "Setiap blok didekripsi independen dengan key yang sama"),
    ("4", "Gabung", "Semua plaintext block digabung"),
    ("5", "Unpad", "PKCS#7 padding dihapus"),
    ("6", "UTF-8", "Bytes hasil dekripsi diubah menjadi teks"),
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



def _render_encryption_overview(process):
    """Menampilkan alur enkripsi ECB secara eksplisit dari input sampai output."""
    st.markdown("### Alur proses enkripsi")

    st.code(
        "Plaintext\n"
        "   ↓ UTF-8 encode\n"
        "Plaintext Bytes\n"
        "   ↓ PKCS#7 padding\n"
        "Padded Bytes\n"
        "   ↓ split 16 byte\n"
        "P1 | P2 | P3 | ... | Pn\n"
        "   ↓ AES-128-ECB dengan key K\n"
        "C1 | C2 | C3 | ... | Cn\n"
        "   ↓ gabungkan + ubah ke HEX\n"
        "Ciphertext HEX",
        language="text",
    )

    st.markdown("#### Apa yang dilakukan ECB pada setiap blok?")
    st.latex(r"C_i = AES_{K}(P_i)")
    st.markdown(
        "Artinya, blok plaintext ke-`i` (**Pᵢ**) dienkripsi menggunakan key AES yang sama "
        "menjadi ciphertext blok ke-`i` (**Cᵢ**). "
        "Tidak ada chaining antara blok: `P2` tidak membutuhkan `C1` dan tidak ada IV."
    )

    cols = st.columns(4)
    items = [
        ("①", "Encode", "Teks → UTF-8 bytes"),
        ("②", "Pad", "Tambah PKCS#7"),
        ("③", "Split", f"Potong tiap {BLOCK_SIZE} byte"),
        ("④", "Encrypt", "AES-128 untuk tiap blok"),
    ]
    for col, (num, title, desc) in zip(cols, items):
        with col:
            st.markdown(f"**{num} {title}**")
            st.caption(desc)

    st.divider()

    st.markdown("#### Data yang mengalir")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Input plaintext**")
        st.code(process.plaintext)
        st.markdown("**UTF-8 bytes (HEX)**")
        st.code(bytes_as_hex(process.plaintext_bytes))
    with c2:
        st.markdown("**Padded bytes (HEX)**")
        st.code(bytes_as_hex(process.padded_bytes))
        st.caption(
            f"{len(process.plaintext_bytes)} byte asli → "
            f"+{process.padding_length} byte padding → "
            f"{len(process.padded_bytes)} byte total."
        )

    st.markdown("#### Pembagian blok sebelum AES")
    block_rows = []
    for step in process.blocks:
        block_rows.append(
            {
                "Blok": f"P{step.index}",
                "Plaintext Block (HEX)": step.plaintext_block_hex,
                "Ukuran": f"{BLOCK_SIZE} byte",
                "Status": "Blok padding" if step.is_padding_block else "Data",
            }
        )
    st.dataframe(block_rows, width="stretch", hide_index=True)

    st.info(
        "Perhatikan bahwa setiap Pᵢ masuk ke AES secara independen. "
        "Itulah inti mode ECB dan juga alasan blok plaintext yang identik "
        "menghasilkan ciphertext yang identik selama key-nya sama."
    )
    st.divider()


def _generate_ecb_key():
    """Generate AES-128 key dan langsung masukkan ke state widget."""
    st.session_state["ecb_encrypt_key"] = generate_random_key(KEY_SIZE).hex()


def _tab_encrypt():
    st.subheader("Enkripsi")

    plaintext = st.text_area(
        "Plaintext",
        placeholder="Contoh: HELLOHELLOHELLO! (coba isi teks berulang untuk lihat kelemahan ECB)",
        height=100,
        key="ecb_plaintext",
    )

    st.caption(f"Key AES-128 wajib {KEY_SIZE} byte. Paling gampang, generate saja key acaknya di bawah ini.")

    if "ecb_encrypt_key" not in st.session_state:
        st.session_state["ecb_encrypt_key"] = ""

    col_gen, col_info = st.columns([1, 2])
    with col_gen:
        st.button(
            "Generate Key Acak",
            use_container_width=True,
            on_click=_generate_ecb_key,
        )
    with col_info:
        st.caption(
            f"Blok AES = {BLOCK_SIZE} byte. Panjang plaintext akan otomatis "
            f"di-*pad* sampai kelipatan {BLOCK_SIZE} byte."
        )

    key_hex = st.text_input(
        "Key (HEX)",
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
    _render_encryption_overview(process)

    st.markdown("### Langkah 1 — Plaintext → UTF-8 → Padding")
    st.caption(
        "Tahap ini mengubah teks menjadi bytes, lalu menambahkan PKCS#7 "
        "agar panjang data menjadi kelipatan 16 byte."
    )
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Plaintext**")
        st.code(plaintext)
    with col2:
        st.markdown("**UTF-8 Bytes (HEX)**")
        st.code(bytes_as_hex(process.plaintext_bytes))

    st.markdown("**Hasil setelah PKCS#7 padding**")
    st.code(bytes_as_hex(process.padded_bytes))
    st.caption(
        f"{len(process.plaintext_bytes)} byte → "
        f"{process.padding_length} byte padding → "
        f"{len(process.padded_bytes)} byte = {len(process.blocks)} blok."
    )

    st.markdown("### Langkah 2 — Key AES-128")
    st.caption(
        "Key 16 byte ini dipakai untuk semua blok. ECB tidak membuat key berbeda "
        "untuk setiap blok."
    )
    st.code(process.key_hex)

    st.markdown("### Langkah 3 — Split menjadi blok 16 byte")
    st.caption(
        f"Data yang sudah di-pad dibagi dari kiri ke kanan menjadi blok berukuran "
        f"{BLOCK_SIZE} byte."
    )
    split_rows = []
    for step in process.blocks:
        split_rows.append(
            {
                "Blok": f"P{step.index}",
                "Plaintext Block (HEX)": step.plaintext_block_hex,
                "Status": "Padding" if step.is_padding_block else "Data",
            }
        )
    st.dataframe(split_rows, width="stretch", hide_index=True)

    st.markdown("### Langkah 4 — AES-ECB per blok")
    st.caption(
        "Setiap blok diproses sendiri. Secara konsep: "
        "**P1 → AES(K) → C1**, **P2 → AES(K) → C2**, dan seterusnya."
    )

    _render_block_table(process.blocks, mode="encrypt")

    duplicates = [b for b in process.blocks if b.duplicate_of_index is not None]
    if duplicates:
        contoh = duplicates[0]
        st.warning(
            f"Blok #{contoh.index} memiliki plaintext yang sama dengan blok "
            f"#{contoh.duplicate_of_index}; ciphertext-nya juga identik. "
            "Ini adalah karakteristik sekaligus kelemahan mode ECB."
        )

    with st.expander("Detail transformasi setiap blok", expanded=True):
        for step in process.blocks:
            label = " — blok padding" if step.is_padding_block else ""
            st.markdown(f"**P{step.index}{label} → C{step.index}**")
            col1, col2, col3 = st.columns([1, 0.2, 1])
            with col1:
                st.markdown("Plaintext block")
                st.code(step.plaintext_block_hex)
            with col2:
                st.markdown(" ")
                st.markdown("**AES**")
                st.markdown("↓")
                st.caption("key sama")
            with col3:
                st.markdown("Ciphertext block")
                st.code(step.ciphertext_block_hex)
            st.divider()

    st.markdown("### Langkah 5 — Gabungkan ciphertext")
    st.caption(
        "Semua ciphertext block digabung sesuai urutan. Tidak ada chaining antarblok."
    )
    st.code(process.ciphertext_hex)

    st.success("Enkripsi selesai.")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Ciphertext (HEX)**")
        st.code(process.ciphertext_hex)
    with col2:
        st.markdown("**Key (HEX)**")
        st.code(process.key_hex)
    st.caption(
        "Untuk dekripsi, masukkan pasangan ciphertext dan key yang sama pada tab Dekripsi."
    )


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

    st.markdown("### Langkah 1 — Ciphertext HEX → Bytes → Blok")
    st.code(bytes_as_hex(ciphertext))
    st.caption(
        f"{len(ciphertext)} byte ciphertext → "
        f"{len(steps)} blok × {BLOCK_SIZE} byte."
    )

    st.markdown("### Langkah 2 — Key AES-128")
    st.caption("Gunakan key yang sama persis dengan saat enkripsi.")
    st.code(key.hex())

    st.markdown("### Langkah 3 — AES-ECB per blok")
    st.caption("Urutannya dibalik dari enkripsi: **C1 → AES⁻¹(K) → P1**, dan seterusnya.")
    _render_block_table(steps, mode="decrypt")

    with st.expander("Detail transformasi setiap blok", expanded=True):
        for step in steps:
            st.markdown(f"**C{step.index} → P{step.index}**")
            col1, col2, col3 = st.columns([1, 0.2, 1])
            with col1:
                st.markdown("Ciphertext block")
                st.code(step.ciphertext_block_hex)
            with col2:
                st.markdown(" ")
                st.markdown("**AES⁻¹**")
                st.markdown("↓")
                st.caption("key sama")
            with col3:
                st.markdown("Plaintext block")
                st.code(step.plaintext_block_hex)
            st.divider()

    st.markdown("### Langkah 4 — Gabungkan → Unpad → UTF-8")
    st.caption(
        "Plaintext block digabung, padding PKCS#7 dibuang, lalu bytes hasilnya "
        "diubah kembali menjadi teks UTF-8."
    )

    st.markdown("**Plaintext hasil dekripsi**")
    st.success("Dekripsi berhasil.")
    st.text_area(
        "Plaintext hasil dekripsi",
        plaintext,
        height=100,
        disabled=True,
    )


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