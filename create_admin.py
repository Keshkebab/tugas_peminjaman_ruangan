"""Bikin user admin, atau jadikan user yang sudah ada sebagai admin.

Taruh di folder yang sama dengan main.py / database.py, lalu jalankan:

    python create_admin.py
        -> tanya email, nama, password secara interaktif

    python create_admin.py --email admin@kampus.ac.id --nama "Admin Kampus"
        -> kalau email belum ada: dibuat sebagai admin
        -> kalau sudah ada: role jadi admin + password diganti (nama ikut diganti kalau diisi)

    python create_admin.py --email budi@kampus.ac.id --promote
        -> user yang sudah ada dijadikan admin, password TIDAK diubah
"""
import argparse
import getpass
import sys

import bcrypt

from database import get_cursor

USER_COLS = "id, nama, email, role, no_hp"


def minta_password() -> str:
    while True:
        pw = getpass.getpass("Password (min. 6 karakter): ")
        if len(pw) < 6:
            print("Terlalu pendek, minimal 6 karakter.")
            continue
        if len(pw.encode()) > 72:
            print("Terlalu panjang, maksimal 72 byte (batas bcrypt).")
            continue
        if pw != getpass.getpass("Ulangi password: "):
            print("Password tidak sama, ulangi.")
            continue
        return pw


def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()


def main():
    ap = argparse.ArgumentParser(description="Buat / promosikan user menjadi admin")
    ap.add_argument("--email")
    ap.add_argument("--nama")
    ap.add_argument("--password", help="kalau dikosongkan akan ditanya lewat prompt (lebih aman, tidak masuk history)")
    ap.add_argument("--no-hp", dest="no_hp")
    ap.add_argument("--promote", action="store_true", help="hanya ubah role user yang sudah ada jadi admin")
    a = ap.parse_args()

    email = (a.email or input("Email: ")).strip()
    if not email:
        sys.exit("Email wajib diisi.")

    with get_cursor() as cur:
        cur.execute("SELECT id, nama, role FROM users WHERE email = %s", (email,))
        ada = cur.fetchone()

        # ---- mode promote: cuma ganti role ----
        if a.promote:
            if not ada:
                sys.exit(f"User dengan email {email} tidak ditemukan.")
            cur.execute(f"UPDATE users SET role = 'admin' WHERE id = %s RETURNING {USER_COLS}", (ada["id"],))
            u = cur.fetchone()
            print(f"OK: {u['nama']} ({u['email']}) sekarang admin. Password tidak diubah.")
            return

        # ---- user sudah ada: jadikan admin + reset password ----
        if ada:
            pw = a.password or minta_password()
            nama = a.nama or ada["nama"]
            cur.execute(
                f"""UPDATE users SET nama = %s, password_hash = %s, role = 'admin'
                    WHERE id = %s RETURNING {USER_COLS}""",
                (nama, hash_password(pw), ada["id"]),
            )
            u = cur.fetchone()
            print(f"OK: user lama {u['email']} dijadikan admin dan password diganti.")
            return

        # ---- user baru ----
        nama = a.nama or input("Nama [Administrator]: ").strip() or "Administrator"
        pw = a.password or minta_password()
        cur.execute(
            f"""INSERT INTO users (nama, email, password_hash, role, no_hp)
                VALUES (%s, %s, %s, 'admin', %s) RETURNING {USER_COLS}""",
            (nama, email, hash_password(pw), a.no_hp),
        )
        u = cur.fetchone()
        print(f"OK: admin baru dibuat (id={u['id']}, email={u['email']}).")


if __name__ == "__main__":
    main()