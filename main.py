"""
Aplikasi Kriptografi — Tugas Materi 5 (Algoritma Kriptografi Modern)

File ini sengaja dibuat SEPENDEK MUNGKIN.
Tugasnya cuma 2:
1. Menyediakan menu (sidebar) untuk 5 sub-aplikasi sesuai soal tugas.
2. Memanggil fungsi render() dari halaman yang dipilih.

Semua logic algoritma ada di folder ciphers/
Semua tampilan tiap menu ada di folder pages_ui/

Kalau mau nambah/ganti menu, cukup edit dictionary MENUS di bawah —
tidak perlu menyentuh bagian lain di file ini.
"""

import streamlit as st

from pages_ui.xor_page import render as render_xor
from pages_ui.coming_soon_page import render as render_coming_soon


st.set_page_config(
    page_title="Kriptografi - Materi 5",
    page_icon="🔐",
    layout="wide",
)

# ============================================================
# DAFTAR MENU
# Sesuai soal tugas: 2 klasik, 2 modern, 1 super enkripsi (gabungan 4).
# ============================================================

MENUS = {
    "1. Cipher Klasik A": {"icon": "📜", "kind": "coming_soon"},
    "2. Cipher Klasik B": {"icon": "📜", "kind": "coming_soon"},
    "3. XOR Cipher (Modern)": {"icon": "🔐", "kind": "xor"},
    "4. Cipher Modern Lain": {"icon": "🧩", "kind": "coming_soon"},
    "5. Super Enkripsi": {"icon": "🧬", "kind": "coming_soon"},
}


def main():
    st.sidebar.title("🔐 Kriptografi")
    st.sidebar.caption("Materi 5 — Algoritma Kriptografi Modern")
    st.sidebar.divider()

    pilihan = st.sidebar.radio(
        "Pilih menu",
        list(MENUS.keys()),
        format_func=lambda nama: f"{MENUS[nama]['icon']}  {nama}",
    )

    st.sidebar.divider()
    st.sidebar.caption("Tugas kelompok — Kriptografi")

    menu = MENUS[pilihan]

    if menu["kind"] == "xor":
        render_xor()
    else:
        render_coming_soon(pilihan)


if __name__ == "__main__":
    main()
