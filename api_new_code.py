# api_new_code.py
# HANI MOTOR – Minimal API for "ساخت کد جدید" page
# سازگار با پروژه‌های ساده Flask + SQLite
# اگر از SQLAlchemy یا مسیر DB خاص استفاده می‌کنی، فقط تابع get_conn را مطابق خودت کن.

from flask import Blueprint, request, jsonify, current_app
import sqlite3
import os

newcode_api = Blueprint("newcode_api", __name__, url_prefix="/api")

# --- DB autodetect: اگر مسیر DB را در env بدهی از آن استفاده می‌کند ---
def _guess_db_path():
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.environ.get("HANI_DB_PATH"),
        os.path.join(here, "coding.db"),
        os.path.join(here, "database.db"),
        os.path.join(here, "app.db"),
    ]
    for p in candidates:
        if p and os.path.exists(p):
            return p
    # اگر هیچ‌کدام نبود، coding.db می‌سازد (در کنار فایل)
    return os.path.join(here, "coding.db")

DB_PATH = _guess_db_path()

def get_conn():
    # اگر پروژه‌ات اتصال مرکزی دارد، همین تابع را با آن جایگزین کن.
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def ensure_tables():
    """ جدول مورد نیاز را اگر نبود می‌سازد (بی‌خطر) """
    con = get_conn()
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS coding_structure (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            layer_level INTEGER NOT NULL,
            parent_id INTEGER
        )
    """)
    con.commit()
    con.close()

@newcode_api.route("/ping")
def ping():
    return jsonify({"ok": True, "db": DB_PATH})

@newcode_api.route("/options")
def options():
    """
    GET /api/options?level=1..6&parent=<id?>
    خروجی: [{id, name}]
    """
    ensure_tables()
    level = int(request.args.get("level", "1"))
    parent = request.args.get("parent", None)

    q = "SELECT id, name FROM coding_structure WHERE layer_level=?"
    params = [level]

    if parent is None or str(parent).strip() in ("", "null", "None"):
        q += " AND (parent_id IS NULL OR parent_id='')"
    else:
        try:
            pid = int(parent)
            q += " AND parent_id=?"
            params.append(pid)
        except ValueError:
            return jsonify([])

    try:
        con = get_conn()
        rows = con.execute(q, params).fetchall()
        con.close()
        data = [{"id": r["id"], "name": r["name"]} for r in rows]
        return jsonify(data)
    except Exception as e:
        # برای دیباگ موقت:
        current_app.logger.exception("options error: %s", e)
        return jsonify([]), 500

@newcode_api.route("/summary")
def summary():
    """
    GET /api/summary?selections=1,5,9,12,20,33
    خروجی: {code, description}
    """
    ensure_tables()
    csv = (request.args.get("selections") or "").strip()
    if not csv:
        return jsonify({"code": "", "description": ""})

    ids = []
    for p in csv.split(","):
        p = p.strip()
        if p.isdigit():
            ids.append(int(p))
    if not ids:
        return jsonify({"code": "", "description": ""})

    try:
        con = get_conn()
        q = f"SELECT id, name FROM coding_structure WHERE id IN ({','.join(['?']*len(ids))})"
        rows = con.execute(q, ids).fetchall()
        con.close()
        name_by_id = {r["id"]: r["name"] for r in rows}
        code = "-".join([str(x) for x in ids])
        desc = " | ".join([f"لایه {i+1}: {name_by_id.get(cid, f'#{cid}')}" for i, cid in enumerate(ids)])
        return jsonify({"code": code, "description": desc})
    except Exception as e:
        current_app.logger.exception("summary error: %s", e)
        return jsonify({"code": "", "description": ""})

@newcode_api.route("/save", methods=["POST"])
def save():
    """
    POST /api/save
    body: { selections: {...}, code: "...", description: "..." }
    این نسخه فقط echo می‌کند (DB شما ممکن است جدول دیگری برای ذخیره داشته باشد).
    """
    data = request.get_json(silent=True) or {}
    code = (data.get("code") or "").strip()
    description = (data.get("description") or "").strip()
    selections = data.get("selections") or {}
    if not code:
        return jsonify({"ok": False, "error": "کد خالی است"}), 400
    return jsonify({"ok": True, "code": code, "description": description, "selections": selections})
