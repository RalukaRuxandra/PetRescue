import os
import sqlite3
from typing import Optional, Dict, Any, List

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    abort,
)

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "petrescue.db")

UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


@app.context_processor
def inject_globals():
    # Available in all templates
    return {
        "current_user": current_user(),
        "current_admin": current_admin(),
        "current_shelter": current_shelter(),
    }


# -----------------------
# DB helpers
# -----------------------

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _table_has_column(conn: sqlite3.Connection, table: str, col: str) -> bool:
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table})")
    cols = [r["name"] for r in cur.fetchall()]
    return col in cols


def _ensure_column(conn: sqlite3.Connection, table: str, col: str, col_def: str) -> None:
    if not _table_has_column(conn, table, col):
        cur = conn.cursor()
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_def}")
        conn.commit()


def init_db() -> None:
    conn = get_db()
    cur = conn.cursor()

    # Users
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL DEFAULT '',
            last_name  TEXT NOT NULL DEFAULT '',
            email TEXT NOT NULL UNIQUE,
            phone TEXT NOT NULL DEFAULT '',
            password_hash TEXT NOT NULL
        )
    """)

    # Admins
    cur.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL DEFAULT '',
            email TEXT NOT NULL DEFAULT '',
            phone TEXT NOT NULL DEFAULT '',
            must_reset_password INTEGER NOT NULL DEFAULT 1
        )
    """)

    # Shelters (approved)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS shelters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            phone TEXT NOT NULL DEFAULT '',
            address TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            website TEXT NOT NULL DEFAULT '',
            photo_filename TEXT NOT NULL DEFAULT '',
            password_hash TEXT NOT NULL DEFAULT '',
            shelter_type TEXT NOT NULL DEFAULT 'General',
            urgent_level INTEGER NOT NULL DEFAULT 0,
            pickup_service INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)

    # Shelter requests
    cur.execute("""
        CREATE TABLE IF NOT EXISTS shelter_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL DEFAULT '',
            address TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            website TEXT NOT NULL DEFAULT '',
            photo_filename TEXT NOT NULL DEFAULT '',
            password_hash TEXT NOT NULL DEFAULT '',
            shelter_type TEXT NOT NULL DEFAULT 'General',
            pickup_service INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'PENDING',
            submitted_at TEXT NOT NULL DEFAULT (datetime('now')),
            reviewed_at TEXT
        )
    """)

    # Donations / volunteer intents
    cur.execute("""
        CREATE TABLE IF NOT EXISTS donations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            category TEXT NOT NULL,
            shelter_id INTEGER NOT NULL,
            amount REAL NOT NULL DEFAULT 0,
            details TEXT NOT NULL DEFAULT '',
            message TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(shelter_id) REFERENCES shelters(id)
        )
    """)

    # Animals (uploaded by shelters)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS animals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            shelter_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            species TEXT NOT NULL DEFAULT '',
            age TEXT NOT NULL DEFAULT '',
            story TEXT NOT NULL DEFAULT '',
            photo_filename TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY(shelter_id) REFERENCES shelters(id)
        )
    """)

    # Public reports (animals found / sick / injured)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reporter_name TEXT NOT NULL,
            reporter_phone TEXT NOT NULL DEFAULT '',
            reporter_email TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)

    conn.commit()

    # Safe migrations
    _ensure_column(conn, "admins", "must_reset_password", "INTEGER NOT NULL DEFAULT 1")
    _ensure_column(conn, "shelters", "photo_filename", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "shelters", "password_hash", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "shelters", "shelter_type", "TEXT NOT NULL DEFAULT 'General'")
    _ensure_column(conn, "shelters", "urgent_level", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(conn, "shelters", "pickup_service", "INTEGER NOT NULL DEFAULT 1")
    _ensure_column(conn, "shelter_requests", "photo_filename", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "shelter_requests", "password_hash", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "shelter_requests", "shelter_type", "TEXT NOT NULL DEFAULT 'General'")
    _ensure_column(conn, "shelter_requests", "pickup_service", "INTEGER NOT NULL DEFAULT 1")

    # Create default admin if none exists
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM admins")
    cnt = cur.fetchone()["c"]
    if cnt == 0:
        cur.execute(
            "INSERT INTO admins (username, password_hash, full_name, email, phone, must_reset_password) VALUES (?, ?, ?, ?, ?, ?)",
            ("admin", generate_password_hash("admin"), "Admin", "admin@local", "", 1),
        )
        conn.commit()

    conn.close()


@app.before_request
def _init_db_before_requests():
    init_db()


# -----------------------
# Auth helpers
# -----------------------

def current_user() -> Optional[Dict[str, Any]]:
    user_id = session.get("user_id")
    if not user_id:
        return None
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def current_admin() -> Optional[Dict[str, Any]]:
    admin_id = session.get("admin_id")
    if not admin_id:
        return None
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM admins WHERE id = ?", (admin_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def current_shelter() -> Optional[Dict[str, Any]]:
    shelter_id = session.get("shelter_id")
    if not shelter_id:
        return None
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM shelters WHERE id = ?", (shelter_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def require_admin():
    if not session.get("admin_id"):
        return redirect(url_for("admin_login"))
    return None


def require_user():
    if not session.get("user_id"):
        flash("Pentru a ajuta, trebuie să fii autentificat.", "error")
        return redirect(url_for("ajuta"))
    return None


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def save_uploaded_photo(file_storage) -> str:
    if not file_storage or file_storage.filename == "":
        return ""
    if not allowed_file(file_storage.filename):
        flash("Format poză invalid. Acceptăm: png, jpg, jpeg, webp.", "error")
        return ""
    fname = secure_filename(file_storage.filename)
    base, ext = os.path.splitext(fname)
    candidate = fname
    i = 1
    while os.path.exists(os.path.join(UPLOAD_FOLDER, candidate)):
        candidate = f"{base}_{i}{ext}"
        i += 1
    file_storage.save(os.path.join(UPLOAD_FOLDER, candidate))
    return candidate


# -----------------------
# Public pages
# -----------------------

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/adaposturi")
def adaposturi():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM shelters ORDER BY id DESC")
    shelters = [dict(r) for r in cur.fetchall()]
    conn.close()
    return render_template("shelters.html", shelters=shelters)


@app.route("/raporteaza", methods=["GET", "POST"])
def raporteaza():
    if request.method == "POST":
        reporter_name = (request.form.get("reporter_name") or "").strip()
        reporter_phone = (request.form.get("reporter_phone") or "").strip()
        reporter_email = (request.form.get("reporter_email") or "").strip()
        description = (request.form.get("description") or "").strip()

        if not reporter_name or not description:
            flash("Numele și descrierea sunt obligatorii.", "error")
            return render_template("raporteaza.html")

        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO reports (reporter_name, reporter_phone, reporter_email, description) VALUES (?, ?, ?, ?)",
            (reporter_name, reporter_phone, reporter_email, description),
        )
        conn.commit()
        conn.close()

        return redirect(url_for("raporteaza_confirmare"))

    return render_template("raporteaza.html")


@app.route("/raporteaza/confirmare")
def raporteaza_confirmare():
    return render_template("raporteaza_confirmare.html")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        flash("Mesaj trimis. Mulțumim!", "success")
        return redirect(url_for("contact"))
    return render_template("contact.html")


@app.route("/login")
def login():
    return render_template("login_options.html")


@app.route("/login/utilizator", methods=["GET", "POST"])
def login_utilizator():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        if not email or not password:
            flash("Emailul și parola sunt obligatorii.", "error")
            return render_template("login_user.html", current_user=current_user())

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cur.fetchone()
        conn.close()

        if not user or not check_password_hash(user["password_hash"], password):
            flash("Email sau parolă incorecte.", "error")
            return render_template("login_user.html", current_user=current_user())

        session["user_id"] = int(user["id"])
        flash("Autentificat cu succes.", "success")
        return redirect(url_for("home"))

    return render_template("login_user.html", current_user=current_user())


@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("Te-ai delogat.", "success")
    return redirect(url_for("home"))


@app.route("/login/adapost", methods=["GET", "POST"])
def login_adapost():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        if not email or not password:
            flash("Emailul și parola sunt obligatorii.", "error")
            return render_template("login_shelter.html", current_user=current_user())

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM shelters WHERE email = ?", (email,))
        sh = cur.fetchone()
        conn.close()

        if not sh or not sh["password_hash"] or not check_password_hash(sh["password_hash"], password):
            flash("Email sau parolă incorecte (sau adăpostul nu e aprobat).", "error")
            return render_template("login_shelter.html", current_user=current_user())

        session["shelter_id"] = int(sh["id"])
        flash("Adăpost autentificat.", "success")
        return redirect(url_for("shelter_dashboard"))

    return render_template("login_shelter.html", current_user=current_user())


def require_shelter():
    if not session.get("shelter_id"):
        flash("Trebuie să te autentifici ca adăpost.", "error")
        return redirect(url_for("login_adapost"))
    return None


@app.route("/shelter/logout")
def logout_adapost():
    session.pop("shelter_id", None)
    flash("Te-ai delogat.", "success")
    return redirect(url_for("home"))


@app.route("/shelter/dashboard")
def shelter_dashboard():
    guard = require_shelter()
    if guard:
        return guard

    sh = current_shelter()
    if not sh:
        session.pop("shelter_id", None)
        flash("Sesiune invalidă. Autentifică-te din nou.", "error")
        return redirect(url_for("login_adapost"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM animals WHERE shelter_id = ? ORDER BY id DESC", (sh["id"],))
    animals = [dict(r) for r in cur.fetchall()]
    conn.close()

    return render_template("shelter_dashboard.html", shelter=sh, animals=animals)


@app.route("/shelter/animals/add", methods=["POST"])
def shelter_animals_add():
    guard = require_shelter()
    if guard:
        return guard

    sh = current_shelter()
    if not sh:
        session.pop("shelter_id", None)
        flash("Sesiune invalidă. Autentifică-te din nou.", "error")
        return redirect(url_for("login_adapost"))

    name = (request.form.get("name") or "").strip()
    species = (request.form.get("species") or "").strip()
    age = (request.form.get("age") or "").strip()
    story = (request.form.get("story") or "").strip()

    if not name:
        flash("Numele animalului este obligatoriu.", "error")
        return redirect(url_for("shelter_dashboard"))

    photo_filename = save_uploaded_photo(request.files.get("photo"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO animals (shelter_id, name, species, age, story, photo_filename)
             VALUES (?, ?, ?, ?, ?, ?)""",
        (sh["id"], name, species, age, story, photo_filename),
    )
    conn.commit()
    conn.close()

    flash("Animal adăugat.", "success")
    return redirect(url_for("shelter_dashboard"))


@app.route("/shelter/animals/<int:animal_id>/edit", methods=["GET", "POST"])
def shelter_animals_edit(animal_id: int):
    guard = require_shelter()
    if guard:
        return guard

    sh = current_shelter()
    if not sh:
        session.pop("shelter_id", None)
        flash("Sesiune invalidă. Autentifică-te din nou.", "error")
        return redirect(url_for("login_adapost"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM animals WHERE id = ? AND shelter_id = ?", (animal_id, sh["id"]))
    animal = cur.fetchone()
    if not animal:
        conn.close()
        abort(404)

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        species = (request.form.get("species") or "").strip()
        age = (request.form.get("age") or "").strip()
        story = (request.form.get("story") or "").strip()

        if not name:
            flash("Numele animalului este obligatoriu.", "error")
            conn.close()
            return redirect(url_for("shelter_animals_edit", animal_id=animal_id))

        photo_filename = animal["photo_filename"] or ""
        new_photo = request.files.get("photo")
        if new_photo and new_photo.filename:
            new_saved = save_uploaded_photo(new_photo)
            if new_saved:
                if photo_filename:
                    old_path = os.path.join(UPLOAD_FOLDER, photo_filename)
                    if os.path.exists(old_path):
                        try:
                            os.remove(old_path)
                        except OSError:
                            pass
                photo_filename = new_saved

        cur.execute(
            """UPDATE animals
                 SET name=?, species=?, age=?, story=?, photo_filename=?
                 WHERE id=? AND shelter_id=?""",
            (name, species, age, story, photo_filename, animal_id, sh["id"]),
        )
        conn.commit()
        conn.close()

        flash("Animal actualizat.", "success")
        return redirect(url_for("shelter_dashboard"))

    conn.close()
    return render_template("shelter_animal_edit.html", shelter=sh, animal=dict(animal))


@app.route("/shelter/animals/<int:animal_id>/delete", methods=["POST"])
def shelter_animals_delete(animal_id: int):
    guard = require_shelter()
    if guard:
        return guard

    sh = current_shelter()
    if not sh:
        session.pop("shelter_id", None)
        flash("Sesiune invalidă. Autentifică-te din nou.", "error")
        return redirect(url_for("login_adapost"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT photo_filename FROM animals WHERE id = ? AND shelter_id = ?", (animal_id, sh["id"]))
    row = cur.fetchone()
    if not row:
        conn.close()
        abort(404)

    photo_filename = row["photo_filename"] or ""
    cur.execute("DELETE FROM animals WHERE id = ? AND shelter_id = ?", (animal_id, sh["id"]))
    conn.commit()
    conn.close()

    if photo_filename:
        p = os.path.join(UPLOAD_FOLDER, photo_filename)
        if os.path.exists(p):
            try:
                os.remove(p)
            except OSError:
                pass

    flash("Animal șters.", "success")
    return redirect(url_for("shelter_dashboard"))


@app.route("/register/utilizator", methods=["GET", "POST"])
def register_user():
    if request.method == "POST":
        first_name = (request.form.get("first_name") or "").strip()
        last_name = (request.form.get("last_name") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        phone = (request.form.get("phone") or "").strip()
        password = request.form.get("password") or ""
        password2 = request.form.get("password2") or ""

        if not email or not password:
            flash("Emailul și parola sunt obligatorii.", "error")
            return render_template("register_user.html", current_user=current_user())

        if password != password2:
            flash("Parolele nu coincid.", "error")
            return render_template("register_user.html", current_user=current_user())

        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO users (first_name, last_name, email, phone, password_hash) VALUES (?, ?, ?, ?, ?)",
                (first_name, last_name, email, phone, generate_password_hash(password)),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            flash("Există deja un cont cu acest email.", "error")
            return render_template("register_user.html", current_user=current_user())
        conn.close()

        flash("Cont creat. Te poți autentifica.", "success")
        return redirect(url_for("login_utilizator"))

    return render_template("register_user.html", current_user=current_user())


@app.route("/profil")
def profil():
    u = current_user()
    if not u:
        return redirect(url_for("login_utilizator"))
    return render_template("profil.html", user=u, current_user=u)


@app.route("/profil/edit", methods=["GET", "POST"])
def profil_edit():
    u = current_user()
    if not u:
        return redirect(url_for("login_utilizator"))

    if request.method == "POST":
        first_name = (request.form.get("first_name") or "").strip()
        last_name = (request.form.get("last_name") or "").strip()
        phone = (request.form.get("phone") or "").strip()
        avatar_url = (request.form.get("avatar_url") or "").strip()

        conn = get_db()
        cur = conn.cursor()
        if _table_has_column(conn, "users", "avatar_url"):
            cur.execute(
                "UPDATE users SET first_name=?, last_name=?, phone=?, avatar_url=? WHERE id=?",
                (first_name, last_name, phone, avatar_url, u["id"]),
            )
        else:
            _ensure_column(conn, "users", "avatar_url", "TEXT NOT NULL DEFAULT ''")
            cur.execute(
                "UPDATE users SET first_name=?, last_name=?, phone=?, avatar_url=? WHERE id=?",
                (first_name, last_name, phone, avatar_url, u["id"]),
            )
        conn.commit()
        conn.close()

        flash("Profil actualizat.", "success")
        return redirect(url_for("profil"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id=?", (u["id"],))
    user = cur.fetchone()
    conn.close()
    return render_template("edit_profile.html", user=dict(user), current_user=u)


@app.route("/adaposturi/devino", methods=["GET", "POST"])
def shelter_apply():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        phone = (request.form.get("phone") or "").strip()
        address = (request.form.get("address") or "").strip()
        website = (request.form.get("website") or "").strip()
        description = (request.form.get("description") or "").strip()
        password = request.form.get("password") or ""
        password2 = request.form.get("password2") or ""

        if not name or not email or not password:
            flash("Numele, emailul și parola sunt obligatorii.", "error")
            return render_template("shelter_apply.html", current_user=current_user())

        if password != password2:
            flash("Parolele nu coincid.", "error")
            return render_template("shelter_apply.html", current_user=current_user())

        photo_filename = save_uploaded_photo(request.files.get("photo"))

        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO shelter_requests (name, email, phone, address, description, website, photo_filename, password_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (name, email, phone, address, description, website, photo_filename, generate_password_hash(password)),
        )
        conn.commit()
        conn.close()

        flash("Cerere trimisă. Adminul o va analiza.", "success")
        return redirect(url_for("adaposturi"))

    return render_template("shelter_apply.html", current_user=current_user())


@app.route("/ajuta", methods=["GET", "POST"])
def ajuta():
    if request.method == "POST":
        # form handler is in category
        return redirect(url_for("ajuta"))
    return render_template("ajuta.html")


@app.route("/ajuta/<category>", methods=["GET", "POST"])
def ajuta_category(category: str):
    if category not in ("materials", "money", "volunteer"):
        abort(404)

    u = current_user()
    if not u:
        flash("Pentru a ajuta, trebuie să fii autentificat.", "error")
        return redirect(url_for("login_utilizator"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM shelters ORDER BY urgent_level DESC, id DESC")
    shelters = [dict(r) for r in cur.fetchall()]

    if request.method == "POST":
        mode = request.form.get("mode") or "auto"
        amount = float(request.form.get("amount") or 0)
        details = (request.form.get("details") or "").strip()
        message = (request.form.get("message") or "").strip()
        chosen_ids = request.form.getlist("shelter_ids")

        shelter_id = None
        if mode == "manual" and chosen_ids:
            shelter_id = int(chosen_ids[0])
        else:
            shelter_id = int(shelters[0]["id"]) if shelters else 0

        cur.execute(
            "INSERT INTO donations (user_id, category, shelter_id, amount, details, message) VALUES (?, ?, ?, ?, ?, ?)",
            (u["id"], category, shelter_id, amount, details, message),
        )
        conn.commit()
        conn.close()

        flash("Mulțumim! Cererea ta a fost trimisă.", "success")
        return redirect(url_for("ajuta"))

    conn.close()
    return render_template("ajuta_category.html", category=category, shelters=shelters)


@app.route("/doneaza")
def doneaza_legacy():
    return redirect(url_for("ajuta"))


# -----------------------
# Admin
# -----------------------

@app.route("/admin/", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM admins WHERE username = ?", (username,))
        admin = cur.fetchone()
        conn.close()

        if not admin or not check_password_hash(admin["password_hash"], password):
            flash("Username sau parolă incorecte.", "error")
            return render_template("admin_login.html")

        session["admin_id"] = int(admin["id"])

        if int(admin["must_reset_password"] or 0) == 1:
            return redirect(url_for("admin_reset_password"))

        return redirect(url_for("admin_dashboard"))

    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_id", None)
    flash("Delogat.", "success")
    return redirect(url_for("home"))


@app.route("/admin/reset-password")
def admin_reset_password():
    guard = require_admin()
    if guard:
        return guard
    return render_template("admin_reset_password.html")


@app.route("/admin/reset-password", methods=["POST"])
def admin_reset_password_save():
    guard = require_admin()
    if guard:
        return guard

    password = request.form.get("password") or ""
    password2 = request.form.get("password2") or ""

    if password != password2:
        flash("Parolele nu coincid.", "error")
        return redirect(url_for("admin_reset_password"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "UPDATE admins SET password_hash = ?, must_reset_password = 0 WHERE id = ?",
        (generate_password_hash(password), session["admin_id"]),
    )
    conn.commit()
    conn.close()

    flash("Parolă actualizată.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/dashboard")
def admin_dashboard():
    guard = require_admin()
    if guard:
        return guard

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) AS c FROM users")
    users_count = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) AS c FROM shelters")
    shelters_count = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) AS c FROM shelter_requests WHERE status='PENDING'")
    pending_requests = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) AS c FROM donations")
    donations_count = cur.fetchone()["c"]

    conn.close()

    return render_template(
        "admin_dashboard.html",
        users_count=users_count,
        shelters_count=shelters_count,
        pending_requests=pending_requests,
        donations_count=donations_count,
    )


@app.route("/admin/profile", methods=["GET", "POST"])
def admin_profile():
    guard = require_admin()
    if guard:
        return guard

    conn = get_db()
    cur = conn.cursor()

    if request.method == "POST":
        full_name = (request.form.get("full_name") or "").strip()
        email = (request.form.get("email") or "").strip()
        phone = (request.form.get("phone") or "").strip()

        cur.execute(
            "UPDATE admins SET full_name=?, email=?, phone=? WHERE id=?",
            (full_name, email, phone, session["admin_id"]),
        )
        conn.commit()
        flash("Profil actualizat.", "success")

    cur.execute("SELECT * FROM admins WHERE id=?", (session["admin_id"],))
    admin = cur.fetchone()
    conn.close()

    return render_template("admin_profile.html", admin=dict(admin))


@app.route("/admin/users")
def admin_users():
    guard = require_admin()
    if guard:
        return guard

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users ORDER BY id DESC")
    users = [dict(r) for r in cur.fetchall()]
    conn.close()

    return render_template("admin_users.html", users=users)


@app.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
def admin_user_edit(user_id: int):
    guard = require_admin()
    if guard:
        return guard

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user = cur.fetchone()
    if not user:
        conn.close()
        abort(404)

    if request.method == "POST":
        first_name = (request.form.get("first_name") or "").strip()
        last_name = (request.form.get("last_name") or "").strip()
        phone = (request.form.get("phone") or "").strip()

        cur.execute("UPDATE users SET first_name=?, last_name=?, phone=? WHERE id=?",
                    (first_name, last_name, phone, user_id))
        conn.commit()
        conn.close()

        flash("Utilizator actualizat.", "success")
        return redirect(url_for("admin_users"))

    conn.close()
    return render_template("admin_user_edit.html", user=dict(user))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
def admin_user_delete(user_id: int):
    guard = require_admin()
    if guard:
        return guard

    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()

    flash("Utilizator șters.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/shelter-requests")
def admin_shelter_requests():
    guard = require_admin()
    if guard:
        return guard

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM shelter_requests ORDER BY submitted_at DESC")
    reqs = [dict(r) for r in cur.fetchall()]
    conn.close()

    return render_template("admin_shelter_requests.html", requests=reqs)


@app.route("/admin/shelter-requests/<int:req_id>/approve", methods=["POST"])
def admin_shelter_request_approve(req_id: int):
    guard = require_admin()
    if guard:
        return guard

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM shelter_requests WHERE id=?", (req_id,))
    req = cur.fetchone()
    if not req:
        conn.close()
        abort(404)

    cur.execute(
        """INSERT INTO shelters (name, email, phone, address, description, website, photo_filename, password_hash, shelter_type, pickup_service)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            req["name"], req["email"], req["phone"], req["address"], req["description"],
            req["website"], req["photo_filename"], req["password_hash"],
            req["shelter_type"], req["pickup_service"]
        ),
    )

    cur.execute("UPDATE shelter_requests SET status='APPROVED', reviewed_at=datetime('now') WHERE id=?", (req_id,))
    conn.commit()
    conn.close()

    flash("Cerere aprobată.", "success")
    return redirect(url_for("admin_shelter_requests"))


@app.route("/admin/shelter-requests/<int:req_id>/reject", methods=["POST"])
def admin_shelter_request_reject(req_id: int):
    guard = require_admin()
    if guard:
        return guard

    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE shelter_requests SET status='REJECTED', reviewed_at=datetime('now') WHERE id=?", (req_id,))
    conn.commit()
    conn.close()

    flash("Cerere respinsă.", "success")
    return redirect(url_for("admin_shelter_requests"))


@app.route("/admin/shelters")
def admin_shelters():
    guard = require_admin()
    if guard:
        return guard

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM shelters ORDER BY id DESC")
    shelters = [dict(r) for r in cur.fetchall()]
    conn.close()

    return render_template("admin_shelters.html", shelters=shelters)


@app.route("/admin/shelters/<int:shelter_id>")
def admin_shelter_detail(shelter_id: int):
    guard = require_admin()
    if guard:
        return guard

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM shelters WHERE id=?", (shelter_id,))
    sh = cur.fetchone()
    conn.close()
    if not sh:
        abort(404)
    return render_template("admin_shelter_detail.html", shelter=dict(sh))


@app.route("/admin/shelters/<int:shelter_id>/delete", methods=["POST"])
def admin_shelter_delete(shelter_id: int):
    guard = require_admin()
    if guard:
        return guard

    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM shelters WHERE id=?", (shelter_id,))
    conn.commit()
    conn.close()

    flash("Adăpost șters.", "success")
    return redirect(url_for("admin_shelters"))


if __name__ == "__main__":
    app.run(debug=True)
