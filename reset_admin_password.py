import sqlite3
from pathlib import Path
from werkzeug.security import generate_password_hash

DB_PATH = Path(__file__).with_name("petrescue.db")

ADMIN_USERNAME = "admin"   # <- username-ul adminului
NEW_PASSWORD = "admin123"  # <- parola noua

def main():
    if not DB_PATH.exists():
        raise FileNotFoundError(f"Nu gasesc baza de date: {DB_PATH}")

    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()

        # verifica daca exista userul
        cur.execute("SELECT id, username FROM admins WHERE username = ?", (ADMIN_USERNAME,))
        row = cur.fetchone()
        if not row:
            print(f"❌ Nu exista admin cu username='{ADMIN_USERNAME}'")
            return

        admin_id = row[0]
        new_hash = generate_password_hash(NEW_PASSWORD)

        # actualizeaza parola
        cur.execute(
            "UPDATE admins SET password_hash = ?, must_reset_password = 0 WHERE id = ?",
            (new_hash, admin_id),
        )
        conn.commit()

        print(f"✅ Parola resetata pentru username='{ADMIN_USERNAME}' (id={admin_id})")
        print(f"🔑 Noua parola: {NEW_PASSWORD}")

    finally:
        conn.close()

if __name__ == "__main__":
    main()
