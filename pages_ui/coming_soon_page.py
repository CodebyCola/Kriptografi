"""
Halaman placeholder untuk menu yang belum dikerjakan.

Cara pakai saat kamu mulai mengerjakan menu baru (misal Vigenere Cipher):
1. Buat ciphers/vigenere_cipher.py  -> isi logicnya (seperti xor_cipher.py)
2. Buat pages_ui/vigenere_page.py   -> isi tampilannya (contek xor_page.py)
3. Di main.py, ganti render_coming_soon("Vigenere Cipher") jadi
   `from pages_ui.vigenere_page import render as render_vigenere`
   lalu panggil render_vigenere() pada menu itu.
"""

import streamlit as st


def render(nama_menu: str):
    st.title(f"🚧 {nama_menu}")
    st.info(
        f"Menu **{nama_menu}** belum dikerjakan.\n\n"
        "Tinggal buat file logic di `ciphers/` dan file tampilan di `pages_ui/`, "
        "lalu daftarkan di `main.py` — pola yang sama seperti menu XOR Cipher."
    )
