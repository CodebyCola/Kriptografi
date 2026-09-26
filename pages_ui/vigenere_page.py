"""
Halaman menu: Vigenere Cipher (Algoritma Klasik - Substitusi Polialfabetik).
"""

import html
import streamlit as st
import pandas as pd

from ciphers.vigenere_cipher import (
    vigenere_encrypt,
    vigenere_decrypt,
    get_vigenere_process,
)
from ui_components import flow_diagram

ENCRYPT_STAGES = [
    ("1", "Plaintext", "Teks input"),
    ("2", "Kunci", "Kata kunci berulang"),
    ("3", "Geser Huruf", "Setiap huruf digeser sesuai kunci"),
    ("4", "Ciphertext", "Hasil enkripsi"),
]

DECRYPT_STAGES = [
    ("1", "Ciphertext", "Teks terenkripsi"),
    ("2", "Kunci", "Kata kunci berulang"),
    ("3", "Geser Balik", "Setiap huruf digeser balik sesuai kunci"),
    ("4", "Plaintext", "Hasil dekripsi"),
]

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


# ---------- Helpers ----------

def _span(content, *, color=None, weight=None, size=None, min_width="1.6em"):
    """Span inline dengan style opsional."""
    styles = ["display:inline-block", f"min-width:{min_width}", "text-align:center"]
    if color:
        styles.append(f"color:{color}")
    if weight:
        styles.append(f"font-weight:{weight}")
    if size:
        styles.append(f"font-size:{size}")
    return f"<span style='{';'.join(styles)}'>{content}</span>"


def _validate_inputs(text, key, text_label):
    if not text.strip():
        st.error(f"{text_label} tidak boleh kosong.")
        return False
    if not key.strip():
        st.error("Kunci tidak boleh kosong.")
        return False
    if not key.isalpha() or not key.isascii():
        st.error("Kunci hanya boleh berisi huruf A-Z (tanpa spasi/angka/simbol).")
        return False
    return True


# ---------- Visualisasi ----------

def _build_alignment_html(steps, mode):
    """Baris sejajar: input / kunci / shift / hasil."""
    sign, color = ("+", "#2563eb") if mode == "encrypt" else ("−", "#dc2626")

    rows = {"Input": [], "Kunci": [], "Shift": [], "Hasil": []}
    for s in steps:
        ch = html.escape(s.original_char)
        res = html.escape(s.result_char)
        if s.is_alpha:
            rows["Input"].append(_span(ch.upper(), weight="600"))
            rows["Kunci"].append(_span(s.key_char.upper(), color="#b45309", weight="700"))
            rows["Shift"].append(_span(f"{sign}{s.shift}", color=color, weight="700", size="0.85em"))
            rows["Hasil"].append(_span(res.upper(), color="#059669", weight="700"))
        else:
            rows["Input"].append(_span(ch, color="#6b7280"))
            rows["Kunci"].append(_span("·", color="#9ca3af"))
            rows["Shift"].append(_span("·", color="#9ca3af"))
            rows["Hasil"].append(_span(res, color="#6b7280"))

    label_colors = {"Input": "#374151", "Kunci": "#b45309", "Shift": "#6b7280", "Hasil": "#059669"}

    def row(label, cells):
        return (
            "<div style='display:flex;align-items:center;gap:8px;margin:2px 0'>"
            f"<div style='min-width:70px;font-size:0.8em;color:{label_colors[label]};"
            "font-weight:600;text-align:right'>"
            f"{label}</div>"
            "<div style='font-family:ui-monospace,Menlo,Consolas,monospace;"
            "white-space:nowrap;overflow-x:auto;padding:2px 0'>"
            + "".join(cells) + "</div></div>"
        )

    return (
        "<div style='background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;"
        "padding:10px 12px'>"
        + "".join(row(lbl, rows[lbl]) for lbl in ("Input", "Kunci", "Shift", "Hasil"))
        + "</div>"
    )


def _build_alphabet_strip(step):
    """Alfabet A–Z dengan highlight huruf asli (kuning) & hasil (hijau)."""
    if not step.is_alpha:
        return ""

    ch, res = step.original_char.upper(), step.result_char.upper()
    src, dst = ord(ch) - 65, ord(res) - 65

    def style_for(i):
        if i == src and i == dst:
            return "#a7f3d0", "#065f46", "#059669", "700"
        if i == src:
            return "#fef3c7", "#92400e", "#d97706", "700"
        if i == dst:
            return "#d1fae5", "#065f46", "#059669", "700"
        return "#ffffff", "#374151", "#e5e7eb", "500"

    cells = []
    for i, letter in enumerate(ALPHABET):
        bg, fg, border, weight = style_for(i)
        cells.append(
            f"<span style='display:inline-block;width:1.6em;height:1.6em;"
            f"line-height:1.6em;text-align:center;margin:1px;"
            f"background:{bg};color:{fg};border:1px solid {border};"
            f"border-radius:4px;font-weight:{weight};font-size:0.85em'>"
            f"{letter}</span>"
        )

    return (
        "<div style='margin-top:6px'>"
        "<div style='font-size:0.8em;color:#6b7280;margin-bottom:2px'>"
        f"Alfabet: <span style='color:#92400e;font-weight:700'>{ch}</span> "
        f"→ <span style='color:#065f46;font-weight:700'>{res}</span> "
        f"(geser {step.shift} langkah)</div>"
        + "".join(cells) + "</div>"
    )


def vigenere_visualization(steps, mode):
    if not steps:
        st.info("Tidak ada langkah untuk ditampilkan.")
        return

    st.markdown("##### 🔤 Penjajaran Karakter")
    st.markdown(_build_alignment_html(steps, mode), unsafe_allow_html=True)

    alpha_steps = [s for s in steps if s.is_alpha]
    if not alpha_steps:
        return

    st.markdown("##### 🔎 Detail Pergeseran per Karakter")
    limit = min(len(alpha_steps), 3)
    if len(alpha_steps) > limit:
        st.caption(f"Menampilkan {limit} dari {len(alpha_steps)} karakter berhuruf.")

    for step in alpha_steps[:limit]:
        with st.expander(
            f"Index {step.index}:  {step.original_char.upper()}  →  "
            f"{step.result_char.upper()}  (kunci '{step.key_char.upper()}', shift {step.shift})",
            expanded=False,
        ):
            st.markdown(_build_alphabet_strip(step), unsafe_allow_html=True)


def vigenere_step_table(steps):
    if not steps:
        return
    data = [{
        "Index": s.index,
        "Input": s.original_char,
        "Key Char": s.key_char.upper() if s.is_alpha else "—",
        "Key Index": s.key_index if s.is_alpha else "—",
        "Shift": s.shift if s.is_alpha else "—",
        "Output": s.result_char,
    } for s in steps]
    st.dataframe(pd.DataFrame(data), use_container_width=True, hide_index=True)


# ---------- Halaman ----------

def render():
    st.title("🔐 Vigenere Cipher")
    st.caption("Algoritma Kriptografi Klasik — Substitusi Polialfabetik")

    st.info(
        "Enkripsi: setiap huruf plaintext digeser sejauh nilai huruf kunci yang berulang. "
        "Dekripsi: setiap huruf ciphertext digeser balik sejauh nilai huruf kunci."
    )

    with st.expander("ℹ️ Cara kerja singkat", expanded=False):
        st.markdown(
            "- Kunci berupa kata (hanya huruf) yang diulang sepanjang plaintext.\n"
            "- Setiap huruf kunci dikonversi menjadi angka (A=0, B=1, ..., Z=25).\n"
            "- Huruf plaintext digeser maju sejumlah angka tersebut (mod 26).\n"
            "- Huruf non-alfabet tidak diubah dan tidak memajukan posisi kunci.\n"
            "- Dekripsi melakukan pergeseran mundur dengan kunci yang sama."
        )

    tab_encrypt, tab_decrypt = st.tabs(["🔒 Enkripsi", "🔓 Dekripsi"])
    with tab_encrypt:
        _tab("encrypt")
    with tab_decrypt:
        _tab("decrypt")


def _tab(mode):
    is_encrypt = mode == "encrypt"
    cfg = {
        "title": "Enkripsi" if is_encrypt else "Dekripsi",
        "input_label": "Plaintext" if is_encrypt else "Ciphertext",
        "placeholder": "Contoh: HELLO" if is_encrypt else "Contoh: RIJVS",
        "input_key": f"vigenere_{mode}_" + ("plaintext" if is_encrypt else "ciphertext"),
        "key_key": f"vigenere_{mode}_key",
        "button_key": f"vigenere_{mode}_button",
        "button_label": "🔒 Enkripsi" if is_encrypt else "🔓 Dekripsi",
        "stages": ENCRYPT_STAGES if is_encrypt else DECRYPT_STAGES,
        "process_title": "Proses Pergeseran" if is_encrypt else "Proses Pergeseran Balik",
        "output_title": "Ciphertext" if is_encrypt else "Plaintext",
        "success_msg": "Enkripsi berhasil." if is_encrypt else "Dekripsi berhasil.",
        "transform": vigenere_encrypt if is_encrypt else vigenere_decrypt,
    }

    st.subheader(cfg["title"])

    text = st.text_area(
        cfg["input_label"],
        placeholder=cfg["placeholder"],
        height=100,
        key=cfg["input_key"],
    )
    key = st.text_input(
        "key",
        placeholder="Contoh: KEY",
        max_chars=50,
        key=cfg["key_key"],
    )

    if not st.button(
        cfg["button_label"],
        type="primary",
        use_container_width=True,
        key=cfg["button_key"],
    ):
        return

    if not _validate_inputs(text, key, cfg["input_label"]):
        return

    hasil = cfg["transform"](text, key)
    steps = get_vigenere_process(text, key, mode=mode)

    flow_diagram(cfg["stages"])

    st.markdown(f"#### Tahap 1 — {cfg['input_label']}")
    st.code(text)

    st.markdown(f"#### Tahap 2 — Kunci: `{key.upper()}`")
    st.markdown(f"#### Tahap 3 — {cfg['process_title']}")
    vigenere_visualization(steps, mode=mode)

    with st.expander("📋 Lihat tabel detail", expanded=False):
        vigenere_step_table(steps)

    st.markdown(f"#### Tahap 4 — {cfg['output_title']}")
    st.success(cfg["success_msg"])
    if is_encrypt:
        st.code(hasil)
    else:
        st.text_area(
            "Plaintext hasil dekripsi",
            hasil,
            height=100,
            disabled=True,
            key="vigenere_decrypt_result",
        )