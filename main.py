
import streamlit as st

from pages_ui.ecb_page import render as render_ecb
from pages_ui.caesar_page import render as render_caesar
from pages_ui.vigenere_page import render as render_vigenere
from pages_ui.vernam_page import render as render_vernam
from pages_ui.super_encryption_page import render as render_super_encryption


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
    "1. Caesar Cipher": {"icon": "", "kind": "caesar"},
    "2. vigenere Cipher ": {"icon": "", "kind": "vigenere"},
    "3. ECB Cipher (Modern)": {"icon": "", "kind": "ecb"},
    "4. Vernam Cipher (Modern)": {"icon": "", "kind": "vernam"},
    "5. Super Enkripsi": {"icon": "", "kind": "super_encryption"},
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
    st.sidebar.caption("1. AUSHAF FATHIN IRSYAD NABIL")
    st.sidebar.caption("2. AKBAR FAQIH ADHI")
    st.sidebar.caption("3. MUHAMMAD WINGGA TRIBAYA WAHONO")
    st.sidebar.caption("4. NICOLAUS NARINDRA LIANTO")

    menu = MENUS[pilihan]

    if menu["kind"] == "ecb":
        render_ecb()
    elif menu["kind"] == "caesar":
        render_caesar()
    elif menu["kind"] == "vigenere":
        render_vigenere()
    elif menu["kind"] == "vernam":
        render_vernam()
    elif menu["kind"] == "super_encryption":
        render_super_encryption()


if __name__ == "__main__":
    main()