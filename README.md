# Kriptografi — Tugas Materi 5 (Algoritma Kriptografi Modern)

Aplikasi Streamlit untuk enkripsi & dekripsi, dibuat untuk tugas kelompok.
Soal tugas minta 5 menu: 2 cipher klasik, 2 cipher modern (beda algoritma),
dan 1 menu super enkripsi (gabungan ke-4 algoritma). Struktur project ini
dibuat supaya **setiap orang bisa kerja di file masing-masing** tanpa rebutan
edit satu file besar yang sama.

## Cara menjalankan

```bash
pip install -r requirement.txt
streamlit run main.py
```

## Struktur folder

```
Kriptografi-main/
├── main.py                    # Router menu. Cuma daftar menu + panggil halaman.
├── ui_components.py           # Komponen tampilan yang dipakai bersama semua menu.
├── ciphers/                   # Logic murni tiap algoritma (TANPA kode Streamlit).
│   └── xor_cipher.py
├── pages_ui/                  # Tampilan Streamlit tiap menu (import dari ciphers/).
│   ├── xor_page.py
│   └── coming_soon_page.py    # Placeholder untuk menu yang belum dikerjakan.
├── requirement.txt
└── README.md
```

### Kenapa dipisah jadi 3 lapis (`ciphers/`, `pages_ui/`, `main.py`)?

- **`ciphers/*.py`** — isinya fungsi Python biasa: `encrypt()`, `decrypt()`, dst.
  Tidak boleh ada `import streamlit` di sini. Supaya logic algoritma bisa dites
  sendiri tanpa perlu jalanin aplikasi, dan bisa dipakai ulang di menu Super
  Enkripsi nanti.
- **`pages_ui/*.py`** — isinya tampilan (input, tombol, tabel, penjelasan alur)
  untuk satu menu. File ini yang `import` fungsi dari `ciphers/` lalu
  menampilkan hasilnya.
- **`main.py`** — cuma daftar menu di sidebar dan manggil `render()` dari
  `pages_ui/` yang dipilih. **Jangan taruh logic algoritma atau tampilan detail
  di sini**, supaya file ini tetap pendek walau menu bertambah.

Alurnya: `main.py` → panggil `pages_ui/xxx_page.py` → yang manggil `ciphers/xxx_cipher.py`.

---

## Cara menambah algoritma baru (langkah demi langkah)

Contoh di bawah pakai **Caesar Cipher** sebagai misal, tapi pola yang sama
berlaku untuk Vigenère, Playfair, AES, atau apapun yang jadi jatahmu.

### 1. Buat file logic di `ciphers/`

Buat `ciphers/caesar_cipher.py`. Isinya fungsi murni Python — cukup
`encrypt`, `decrypt`, dan (opsional) fungsi "proses" yang merekam
langkah-langkah untuk ditampilkan di UI. Contek pola `xor_cipher.py`:

```python
# ciphers/caesar_cipher.py

def caesar_encrypt(plaintext: str, shift: int) -> str:
    hasil = ""
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            hasil += chr((ord(ch) - base + shift) % 26 + base)
        else:
            hasil += ch
    return hasil


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    return caesar_encrypt(ciphertext, -shift)
```

Kalau mau nampilin proses per huruf (seperti tabel step di menu XOR), bikin
juga fungsi `get_caesar_process(...)` yang mengembalikan list langkah —
lihat `get_xor_process()` di `ciphers/xor_cipher.py` sebagai contoh polanya
(pakai `@dataclass` biar rapi, bukan dict biasa).

**Aturan penting:** jangan ada `import streamlit` di file ini. Kalau butuh
menampilkan sesuatu, itu urusan file di `pages_ui/`.

### 2. Buat file tampilan di `pages_ui/`

Buat `pages_ui/caesar_page.py`. Ini yang isinya kode Streamlit (input, tombol,
tabel). Struktur minimalnya:

```python
# pages_ui/caesar_page.py

import streamlit as st
from ciphers.caesar_cipher import caesar_encrypt, caesar_decrypt


def render():
    st.title("📜 Caesar Cipher")
    st.caption("Algoritma Kriptografi Klasik — Materi 5")

    tab_encrypt, tab_decrypt = st.tabs(["🔒 Enkripsi", "🔓 Dekripsi"])

    with tab_encrypt:
        plaintext = st.text_area("Plaintext")
        shift = st.number_input("Pergeseran (shift)", min_value=1, max_value=25, value=3)

        if st.button("Enkripsi", type="primary"):
            hasil = caesar_encrypt(plaintext, shift)
            st.success("Enkripsi berhasil.")
            st.code(hasil)

    with tab_decrypt:
        ciphertext = st.text_area("Ciphertext")
        shift = st.number_input("Pergeseran (shift)", min_value=1, max_value=25, value=3, key="dec_shift")

        if st.button("Dekripsi", type="primary"):
            hasil = caesar_decrypt(ciphertext, shift)
            st.success("Dekripsi berhasil.")
            st.code(hasil)
```

Kalau butuh tabel ringkasan proses atau kartu alur algoritma (seperti di menu
XOR), pakai fungsi yang sudah ada di `ui_components.py`
(`flow_diagram()`, dsb) supaya gaya tampilannya seragam antar menu — tidak
perlu bikin ulang dari nol. Boleh juga tambah fungsi baru di
`ui_components.py` kalau butuh komponen yang belum ada, asal memang dipakai
lebih dari satu menu.

### 3. Daftarkan menu di `main.py`

Buka `main.py`, lakukan 2 perubahan kecil:

**a. Tambah import di bagian atas:**

```python
from pages_ui.caesar_page import render as render_caesar
```

**b. Ubah salah satu baris di dictionary `MENUS`**, dari:

```python
"1. Cipher Klasik A": {"icon": "📜", "kind": "coming_soon"},
```

menjadi:

```python
"1. Caesar Cipher": {"icon": "📜", "kind": "caesar"},
```

**c. Tambah pengecekan di fungsi `main()`:**

```python
if menu["kind"] == "xor":
    render_xor()
elif menu["kind"] == "caesar":
    render_caesar()
else:
    render_coming_soon(pilihan)
```

Selesai — jalankan `streamlit run main.py`, menu baru langsung muncul di sidebar.

### Ringkasan: file apa saja yang disentuh untuk 1 algoritma baru

| Aksi | File | Isi |
|---|---|---|
| Buat baru | `ciphers/<nama>_cipher.py` | Fungsi encrypt/decrypt murni |
| Buat baru | `pages_ui/<nama>_page.py` | Tampilan Streamlit untuk menu itu |
| Edit | `main.py` | Tambah 1 baris import + ganti 1 baris di `MENUS` + 1 baris `elif` |

Tidak perlu edit file punya orang lain (`ciphers/xor_cipher.py`,
`pages_ui/xor_page.py`, dll) kecuali memang mau perbaiki bug di situ.
Ini supaya kerja kelompok bisa paralel tanpa saling timpa kode.

---

## Menu Super Enkripsi (menu ke-5)

Menu ini menggabungkan ke-4 algoritma (2 klasik + 2 modern) secara berurutan,
misalnya: `plaintext → Caesar → Vigenère → XOR → AES → ciphertext akhir`.

Karena tiap algoritma sudah dipisah logic-nya di `ciphers/`, menu ini
tinggal **memanggil fungsi encrypt dari 4 file berbeda secara berantai**,
tanpa perlu menulis ulang logic apapun:

```python
# ciphers/super_encryption.py
from ciphers.caesar_cipher import caesar_encrypt, caesar_decrypt
from ciphers.xor_cipher import xor_encrypt, xor_decrypt
# ... import 2 algoritma lainnya

def super_encrypt(plaintext, key_caesar, key_vigenere, key_xor, key_aes):
    step1 = caesar_encrypt(plaintext, key_caesar)
    step2 = vigenere_encrypt(step1, key_vigenere)
    step3 = xor_encrypt(step2, key_xor)
    step4 = aes_encrypt(step3, key_aes)
    return step4
```

Urutan dekripsinya harus **kebalikan** dari urutan enkripsi (algoritma
terakhir didekripsi duluan). Susunan urutan pastinya, silakan didiskusikan
di kelompok — yang penting tiap anggota sudah punya fungsi `encrypt`/`decrypt`
yang bisa dipanggil sendiri-sendiri sebelum menu ini dirakit.