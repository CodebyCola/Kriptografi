
import streamlit as st

from pages_ui.xor_page import render as render_xor
from pages_ui.caesar_page import render as render_caesar
from pages_ui.vigenere_page import render as render_vigenere
from pages_ui.vernam_page import render as render_vernam
from pages_ui.coming_soon_page import render as render_coming_soon


st.set_page_config(
    page_title="Algoritma Kriptografi",
    page_icon="",
    layout="wide",
)

# ============================================================
# DAFTAR MENU
# Sesuai soal tugas: 2 klasik, 2 modern, 1 super enkripsi (gabungan 4).
# ============================================================

MENUS = {
<<<<<<< HEAD
    "1. Caesar Cipher": {"icon": "", "kind": "caesar"},
    "2. vigenere Cipher ": {"icon": "", "kind": "vigenere"},
    "3. XOR Cipher (Modern)": {"icon": "", "kind": "xor"},
    "4. Cipher Modern Lain": {"icon": "", "kind": "coming_soon"},
    "5. Super Enkripsi": {"icon": "", "kind": "coming_soon"},
=======
    "1. Caesar Cipher": {"icon": "📜", "kind": "caesar"},
    "2. vigenere Cipher ": {"icon": "📜", "kind": "vigenere"},
    "3. XOR Cipher (Modern)": {"icon": "🔐", "kind": "xor"},
    "4. Vernam Cipher (Modern)": {"icon": "🗝️", "kind": "vernam"},
    "5. Super Enkripsi": {"icon": "🧬", "kind": "coming_soon"},
>>>>>>> 59c28cc9d0a10e0fb6c364aef65f6f07afc3197d
}


def main():
    st.sidebar.title("Kriptografi")
    st.sidebar.caption("Algoritma Kriptografi")
    st.sidebar.divider()

    pilihan = st.sidebar.radio(
        "Pilih menu",
        list(MENUS.keys()),
        format_func=lambda nama: f"{MENUS[nama]['icon']}  {nama}",
    )

    st.sidebar.divider()
    st.sidebar.caption("Tugas kelompok Kriptografi")

    menu = MENUS[pilihan]

    if menu["kind"] == "xor":
        render_xor()
    elif menu["kind"] == "caesar":
        render_caesar()
    elif menu["kind"] == "vigenere":
        render_vigenere()
    elif menu["kind"] == "vernam":
        render_vernam()
    else:
        render_coming_soon(pilihan)


if __name__ == "__main__":
    main()