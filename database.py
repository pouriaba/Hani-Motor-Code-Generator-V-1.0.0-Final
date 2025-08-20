# --- API for "ساخت کد جدید" (بدون blueprint؛ مستقیم روی app) ---

from flask import request, jsonify

@app.get("/api/ping")
def api_ping():
    return jsonify(ok=True, db=os.path.abspath(DB_NAME))

@app.get("/api/options")
def api_options():
    """
    GET  /api/options?level=1..6&parent=<id?>
    خروجی: [{id, name}]
    name = "CODE — DESCRIPTION"
    """
    try:
        level = int(request.args.get("level", "1"))
    except ValueError:
        return jsonify([])

    parent = request.args.get("parent", None)

    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    if parent is None or str(parent).strip() in ("", "null", "None"):
        cur.execute(
            """
            SELECT id, code, description
            FROM coding_structure
            WHERE layer_level = ? AND parent_id IS NULL
            ORDER BY description ASC
            """,
            (level,),
        )
    else:
        try:
            pid = int(parent)
        except ValueError:
            return jsonify([])
        cur.execute(
            """
            SELECT id, code, description
            FROM coding_structure
            WHERE layer_level = ? AND parent_id = ?
            ORDER BY description ASC
            """,
            (level, pid),
        )

    rows = cur.fetchall()
    conn.close()

    data = [{"id": r["id"], "name": f"{r['code']} — {r['description']}"} for r in rows]
    return jsonify(data)

@app.get("/api/summary")
def api_summary():
    """
    GET  /api/summary?selections=1,5,9,12,20,33
    خروجی: {code, description}
    code از اتصال فیلدهای code (نه id) ساخته می‌شود.
    """
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

    placeholders = ",".join(["?"] * len(ids))
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(
        f"SELECT id, code, description FROM coding_structure WHERE id IN ({placeholders})",
        ids,
    )
    rows = cur.fetchall()
    conn.close()

    by_id = {r["id"]: (r["code"], r["description"]) for r in rows}
    final_code = "-".join([by_id.get(i, (str(i), ""))[0] for i in ids])
    final_desc = " | ".join([f"لایه {idx+1}: {by_id.get(i, ('', f'#{i}'))[1]}" for idx, i in enumerate(ids)])

    return jsonify({"code": final_code, "description": final_desc})

@app.post("/api/save")
def api_save():
    """
    POST /api/save
    body: {selections: {...}, code: "...", description: "..."}
    در جدول generated_products ذخیره می‌کند.
    """
    data = request.get_json(silent=True) or {}
    code = (data.get("code") or "").strip()
    description = (data.get("description") or "").strip()

    if not code:
        return jsonify({"ok": False, "error": "کد خالی است"}), 400

    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO generated_products(full_code, full_description) VALUES (?, ?)",
            (code, description),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"ok": False, "error": "این کد قبلاً ذخیره شده است"}), 409
    conn.close()
    return jsonify({"ok": True})
