# --- IMPORTS ---
from flask import Flask, render_template, request, jsonify, redirect, url_for, g, make_response, session, flash
from markupsafe import Markup
from flask_wtf.csrf import CSRFProtect
import sqlite3
import pandas as pd
import io
import hashlib
from functools import wraps
import math
import jdatetime
from datetime import datetime, timedelta
import re
import math
import time  # ✅ اضافه شد برای نسخه‌دهی استاتیک
import os

app = Flask(__name__)
# --- Session & Security (safe defaults; won't break current behavior) ---
app.secret_key = os.getenv("HANI_SECRET_KEY", "dev-change-me")  # روی سرور مقدار امن بده

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # اگر روی HTTPS هستی True کن
    PERMANENT_SESSION_LIFETIME=60*60*8,  # 8 ساعت
)
csrf = CSRFProtect(app)
@app.after_request
def add_security_headers(response):
    # جلوگیری از MIME sniffing و کلیک‌جکینگ
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")

    # CSP سبک که چیزی را نشکند:
    # - اجازه به اسکریپت‌ها از خودت + jsDelivr + cdnjs + اسکریپت‌های inline (برای فعلاً)
    # - اجازه استایل‌های inline (برای Bootstrap/RTL/…)
    # - اجازه تصاویر data: (آیکون‌های باینری)
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://code.jquery.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "img-src 'self' data:; "
        "font-src 'self' data: https://fonts.gstatic.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net;"
    )
    # فقط اگر قبلاً دستی ست نشده:
    if not response.headers.get("Content-Security-Policy"):
        response.headers.set("Content-Security-Policy", csp)
    return response

# Persian digits filter (بعد از app = Flask(...))
def fa_digits(value):
    if value is None:
        return ''
    s = str(value)
    trans = str.maketrans('0123456789,-', '۰۱۲۳۴۵۶۷۸۹،-')
    return s.translate(trans)

app.jinja_env.filters['fa'] = fa_digits

DB_NAME = 'hami_motor_coding.db'

# جلوگیری از کش استاتیک در حالت توسعه
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0  

# تزریق نسخه برای فایل‌های استاتیک
@app.context_processor
def inject_asset_version():
    return {'asset_v': int(time.time())}  


# --- Custom Jinja Filter for Jalali Date ---
@app.template_filter('to_jalali')
def to_jalali_filter(v):
    """
    پشتیبانی از datetime یا string در چندین فرمت.
    اگر قابل تبدیل نبود، همون مقدار اولیه برگردونده میشه.
    """
    if not v:
        return "N/A"
    try:
        # اگر datetime بود
        if isinstance(v, datetime):
            gdt = v
        else:
            s = str(v).strip()
            # حذف میلی‌ثانیه و Z اگر بود
            s = s.replace('Z', '').split('.')[0]
            # تلاش با ISO
            try:
                gdt = datetime.fromisoformat(s)
            except Exception:
                # تلاش با چند فرمت رایج
                fmts = ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y/%m/%d %H:%M:%S", "%Y/%m/%d"]
                gdt = None
                for fmt in fmts:
                    try:
                        gdt = datetime.strptime(s, fmt)
                        break
                    except Exception:
                        pass
                if gdt is None:
                    return s  # نتونستیم تبدیل کنیم

        return jdatetime.datetime.fromgregorian(datetime=gdt).strftime('%Y/%m/%d')
    except Exception:
        return "N/A"

@app.template_filter('to_farsi_digits')
def to_farsi_digits_filter(s):
    try:
        s = str(s)
        farsi_digits = '۰۱۲۳۴۵۶۷۸۹'
        english_digits = '0123456789'
        translation_table = str.maketrans(english_digits, farsi_digits)
        return s.translate(translation_table)
    except:
        return s

# --- Database Management & Helpers ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB_NAME)
        db.execute("PRAGMA foreign_keys=ON;")   # فعال‌سازی قیود کلید خارجی
        db.execute("PRAGMA journal_mode=WAL;")  # بهبود همزمانی/پایداری نوشتن
        db.row_factory = sqlite3.Row
    return db


def ensure_user_created_at_column():
    db = get_db()
    cols = [r['name'] for r in db.execute("PRAGMA table_info(users)").fetchall()]
    if 'created_at' not in cols:
        db.execute("ALTER TABLE users ADD COLUMN created_at TEXT")
        db.commit()

def backfill_user_created_at():
    db = get_db()
    # هر رکوردی که created_at خالی دارد را با زمان فعلی پر کن
    db.execute("UPDATE users SET created_at = COALESCE(created_at, CURRENT_TIMESTAMP)")
    db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def hash_password(password): return hashlib.sha256(password.encode()).hexdigest()

def log_activity(action, target_id=None):
    if 'user_id' in session:
        db = get_db()
        db.execute("INSERT INTO activity_log (user_id, username, action, target_id) VALUES (?, ?, ?, ?)",
                   (session.get('user_id'), session.get('username'), action, target_id))
        db.commit()

def is_password_strong(password):
    if len(password) < 8: return False, "رمز عبور باید حداقل ۸ کاراکتر باشد."
    if not re.search(r"[a-z]", password): return False, "رمز عبور باید شامل حروف کوچک انگلیسی باشد."
    if not re.search(r"[A-Z]", password): return False, "رمز عبور باید شامل حروف بزرگ انگلیسی باشد."
    if not re.search(r"[0-9]", password): return False, "رمز عبور باید شامل اعداد باشد."
    return True, ""

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('برای دسترسی به این صفحه باید وارد شوید.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            flash('شما دسترسی لازم برای مشاهده این صفحه را ندارید.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.context_processor
def inject_notifications():
    if 'role' in session and session['role'] == 'admin':
        try:
            db = get_db()
            unread_count = db.execute(
                "SELECT COUNT(id) FROM notifications WHERE is_read = 0"
            ).fetchone()[0]
            return dict(unread_notifications=unread_count)
        except sqlite3.OperationalError:
            # اگر جدول هنوز وجود نداشت، خطا نمی‌دهد
            return dict(unread_notifications=0)
    return dict(unread_notifications=0)

# --- User & Auth Routes (UNCHANGED)---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session: return redirect(url_for('index'))
    if request.method == 'POST':
        username, password = request.form['username'], request.form['password']
        user = get_db().execute('SELECT * FROM users WHERE username = ? AND password_hash = ?', (username, hash_password(password))).fetchone()
        if user:
            session['user_id'], session['username'], session['role'] = user['id'], user['username'], user['role']
            log_activity(f"کاربر '{username}' وارد سیستم شد."); flash('شما با موفقیت وارد شدید.', 'success')
            return redirect(url_for('dashboard')) if user['role'] == 'admin' else redirect(url_for('index'))
        else: flash('نام کاربری یا رمز عبور اشتباه است.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_activity(f"کاربر '{session.get('username')}' از سیستم خارج شد."); session.clear()
    flash('شما با موفقیت خارج شدید.', 'info'); return redirect(url_for('login'))

@app.route('/manage_users')
@admin_required
def manage_users():
    db = get_db()

    # تضمین وجود ستون و پر کردن خالی‌ها
    ensure_user_created_at_column()
    backfill_user_created_at()

    stats = {
        'total': db.execute("SELECT COUNT(id) FROM users").fetchone()[0],
        'admins': db.execute("SELECT COUNT(id) FROM users WHERE role = 'admin'").fetchone()[0],
        'users': db.execute("SELECT COUNT(id) FROM users WHERE role = 'user'").fetchone()[0]
    }
    users = db.execute("SELECT id, username, role, created_at FROM users ORDER BY username").fetchall()
    return render_template('manage_users.html', users=users, stats=stats)

@app.route('/add_user', methods=['GET', 'POST'])
@admin_required
def add_user():
    if request.method == 'POST':
        username, password, role = request.form['username'], request.form['password'], request.form['role']
        if not username or not password:
            flash('نام کاربری و رمز عبور الزامی است.', 'danger'); return redirect(url_for('add_user'))
        is_strong, message = is_password_strong(password)
        if not is_strong:
            flash(message, 'danger'); return redirect(url_for('add_user'))
        db = get_db()
        try:
            cursor = db.execute(
                'INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)',
                (username, hash_password(password), role)
            )
            log_activity(f"کاربر جدید '{username}' با نقش '{role}' را ثبت کرد.", cursor.lastrowid); flash(f'کاربر {username} با موفقیت ساخته شد.', 'success')
        except sqlite3.IntegrityError: flash('این نام کاربری قبلا ثبت شده است.', 'danger')
        return redirect(url_for('manage_users'))
    return render_template('add_user.html')

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        flash('کاربر مورد نظر یافت نشد.', 'danger')
        return redirect(url_for('manage_users'))

    if request.method == 'POST':
        # Get new values from the form
        new_username = request.form.get('new_username').strip()
        new_role = request.form.get('role')
        new_password = request.form.get('password')
        
        # --- Start of New Logic ---
        
        current_username = user['username']
        actions_logged = []

        # 1. Handle Username Change
        if new_username and new_username != current_username:
            if current_username == 'admin':
                flash('امکان تغییر نام کاربری اصلی ادمین وجود ندارد.', 'danger')
                return redirect(url_for('manage_users'))
            
            # Check if the new username is already taken
            existing_user = db.execute("SELECT id FROM users WHERE username = ? AND id != ?", (new_username, user_id)).fetchone()
            if existing_user:
                flash(f'نام کاربری «{new_username}» قبلاً توسط کاربر دیگری استفاده شده است.', 'danger')
                return redirect(url_for('manage_users'))
            
            db.execute("UPDATE users SET username = ? WHERE id = ?", (new_username, user_id))
            actions_logged.append(f"نام کاربری '{current_username}' را به '{new_username}' تغییر داد.")
            current_username = new_username # Update for subsequent logs

        # 2. Handle Role Change
        if new_role and new_role != user['role']:
            if user['username'] == 'admin' and new_role != 'admin':
                flash('امکان تغییر نقش کاربر اصلی ادمین وجود ندارد.', 'danger')
                return redirect(url_for('manage_users'))
            
            db.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
            actions_logged.append(f"نقش کاربر '{current_username}' را به '{new_role}' تغییر داد.")

        # 3. Handle Password Change
        if new_password:
            is_strong, message = is_password_strong(new_password)
            if not is_strong:
                flash(message, 'danger')
                return redirect(url_for('manage_users'))
            
            db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(new_password), user_id))
            actions_logged.append(f"رمز عبور کاربر '{current_username}' را تغییر داد.")

        # 4. Commit and Log
        if actions_logged:
            db.commit()
            for action in actions_logged:
                log_activity(action, user_id)
            flash(f"اطلاعات کاربر {current_username} با موفقیت به‌روزرسانی شد.", 'success')
        else:
            flash('هیچ تغییری برای ذخیره وجود نداشت.', 'info')
            
        # --- End of New Logic ---

        return redirect(url_for('manage_users'))

    # This part for GET request remains the same
    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    db = get_db()
    user = db.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()

    if not user:
        flash('کاربر مورد نظر یافت نشد.', 'danger')
        return redirect(url_for('manage_users'))

    if user['username'] == 'admin':
        flash('امکان حذف کاربر اصلی ادمین وجود ندارد.', 'danger')
        return redirect(url_for('manage_users'))
    
    try:
        # --- START: منطق جدید برای حل مشکل Foreign Key ---
        # قبل از حذف کاربر، وابستگی‌های او را در جداول دیگر به NULL تغییر می‌دهیم
        db.execute("UPDATE activity_log SET user_id = NULL WHERE user_id = ?", (user_id,))
        db.execute("UPDATE notifications SET user_id = NULL WHERE user_id = ?", (user_id,))
        
        # حالا کاربر را با خیال راحت حذف می‌کنیم
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.commit()
        # --- END: پایان منطق جدید ---

        log_activity(f"کاربر '{user['username']}' را حذف کرد.", user_id)
        flash(f"کاربر {user['username']} با موفقیت حذف شد.", 'success')
    
    except sqlite3.Error as e:
        db.rollback()
        flash(f'خطا در حذف کاربر: {e}', 'danger')

    return redirect(url_for('manage_users'))

# --- Main Application Routes (UNCHANGED)---
@app.route('/')
@login_required
def index():
    db = get_db()
    layer1_items = db.execute("SELECT * FROM coding_structure WHERE layer_level = 1 AND is_archived = 0 ORDER BY code").fetchall()
    return render_template('index.html', layer1_items=layer1_items)

# در فایل main.py
@app.route('/dashboard')
@admin_required
def dashboard():
    db = get_db()
    stats = {
        'total_codes': db.execute("SELECT COUNT(id) FROM generated_products").fetchone()[0],
        'total_parameters': db.execute("SELECT COUNT(id) FROM coding_structure").fetchone()[0],
        'total_users': db.execute("SELECT COUNT(id) FROM users").fetchone()[0]
    }
    recent_logs = db.execute("SELECT * FROM activity_log ORDER BY timestamp DESC LIMIT 5").fetchall()

    # نسخه نهایی و مقاوم‌شده کوئری
    query = """
        SELECT
            cs.description as class_name,
            COUNT(gp.id) as code_count
        FROM
            generated_products gp
        JOIN
            coding_structure cs ON TRIM(SUBSTR(gp.full_code, 1, 2)) = CAST(cs.code AS TEXT)
        WHERE
            cs.layer_level = 1
        GROUP BY
            cs.description
        HAVING
            COUNT(gp.id) > 0
        ORDER BY
            code_count DESC;
    """

    donut_chart_data_raw = db.execute(query).fetchall()
    donut_chart_data = {
        'labels': [row['class_name'] for row in donut_chart_data_raw],
        'data': [row['code_count'] for row in donut_chart_data_raw]
    }
    return render_template('dashboard.html', stats=stats, recent_logs=recent_logs, donut_chart_data=donut_chart_data)

@app.route('/codes')
@login_required
def view_codes():
    db = get_db()
    page = request.args.get('page', 1, type=int)
    # CHANGE: Set the number of items per page to 10
    per_page = 10

    search_term, class_filter, start_date_jalali, end_date_jalali = request.args.get('search', ''), request.args.get('class_code', ''), request.args.get('start_date', ''), request.args.get('end_date', '')

    base_query, where_clauses, params = "FROM generated_products", [], []
    if search_term: where_clauses.append("(full_code LIKE ? OR full_description LIKE ?)"); params.extend([f"%{search_term}%", f"%{search_term}%"])
    if class_filter: where_clauses.append("full_code LIKE ?"); params.append(f"{class_filter}-%")
    if start_date_jalali:
        try: where_clauses.append("date(created_at) >= ?"); params.append(jdatetime.datetime.strptime(start_date_jalali, '%Y/%m/%d').togregorian().strftime('%Y-%m-%d'))
        except (ValueError, TypeError): flash('فرمت تاریخ شروع نامعتبر است.', 'danger')
    if end_date_jalali:
        try: where_clauses.append("date(created_at) <= ?"); params.append(jdatetime.datetime.strptime(end_date_jalali, '%Y/%m/%d').togregorian().strftime('%Y-%m-%d'))
        except (ValueError, TypeError): flash('فرمت تاریخ پایان نامعتبر است.', 'danger')

    if where_clauses: base_query += " WHERE " + " AND ".join(where_clauses)

    total_codes = db.execute("SELECT COUNT(id) " + base_query, params).fetchone()[0]
    total_pages = math.ceil(total_codes / per_page)

    offset = (page - 1) * per_page
    final_params = list(params)
    final_params.extend([per_page, offset])

    codes_on_page = db.execute("SELECT * " + base_query + " ORDER BY created_at DESC LIMIT ? OFFSET ?", final_params).fetchall()
    all_classes = db.execute("SELECT code, description FROM coding_structure WHERE layer_level = 1").fetchall()

    filters = {'search': search_term, 'class_code': class_filter, 'start_date': start_date_jalali, 'end_date': end_date_jalali}
    start_tour = request.args.get('tour') == 'true'

    return render_template('view_codes.html', codes=codes_on_page, page=page, total_pages=total_pages, all_classes=all_classes, filters=filters, start_tour=start_tour)

@app.route('/generate_code', methods=['POST'])
@login_required
def generate_code():
    db = get_db()
    full_code_parts = []
    full_desc_parts = []
    
    # --- بخش ۱: جمع‌آوری ۶ لایه اول (بدون تغییر) ---
    for i in range(1, 7):
        item_id = request.form.get(f'layer_{i}')
        if not item_id:
            flash(f"خطا: لایه {i} انتخاب نشده است.", 'danger')
            return redirect(url_for('index'))
        
        try:
            item = db.execute("SELECT code, description FROM coding_structure WHERE id = ?", (item_id,)).fetchone()
            if item:
                full_code_parts.append(item['code'])
                full_desc_parts.append(item['description'])
            else:
                flash(f"خطا: آیتم نامعتبر برای لایه {i}.", 'danger')
                return redirect(url_for('index'))
        except Exception as e:
            flash(f"خطای دیتابیس در لایه {i}: {e}", 'danger')
            return redirect(url_for('index'))

    # --- بخش ۲: منطق جدید و اصلاح‌شده برای تولید سریال لایه هفتم ---
    desc_layer_7 = request.form.get('layer_7_text', 'فاقد شرح').strip()
    if not desc_layer_7:
        flash("خطا: شرح کامل و نهایی کالا (لایه ۷) نمی‌تواند خالی باشد.", 'danger')
        return redirect(url_for('index'))
    
    # ۱. ساخت پیش‌کد بر اساس ۶ لایه اول
    parent_prefix = '-'.join(full_code_parts) + '-'
    
    # ۲. جستجو در جدول صحیح (generated_products) برای یافتن بزرگترین سریال
    query = "SELECT full_code FROM generated_products WHERE full_code LIKE ?"
    matching_codes = db.execute(query, (parent_prefix + '%',)).fetchall()
    
    max_serial = 0
    if matching_codes:
        for row in matching_codes:
            try:
                # جدا کردن بخش سریال (آخرین بخش کد) و تبدیل به عدد
                serial_part = int(row['full_code'].split('-')[-1])
                if serial_part > max_serial:
                    max_serial = serial_part
            except (ValueError, IndexError):
                # نادیده گرفتن کدهایی که فرمت اشتباه دارند
                continue
    
    # ۳. محاسبه سریال جدید
    new_serial_num = max_serial + 1
    new_serial_str = str(new_serial_num).zfill(3)
    
    # اضافه کردن بخش هفتم به لیست‌ها
    full_code_parts.append(new_serial_str)
    full_desc_parts.append(desc_layer_7)

    # --- بخش ۳: آماده‌سازی نتیجه نهایی (بدون تغییر) ---
    full_code_dashed = '-'.join(full_code_parts)
    full_code_no_dash = ''.join(full_code_parts)
    full_description = ' / '.join(full_desc_parts)
    
    is_duplicate = db.execute("SELECT id FROM generated_products WHERE full_code = ?", (full_code_dashed,)).fetchone() is not None
    start_tour_on_result = request.form.get('start_tour_on_result') == 'true'
    
    selections = {f'layer_{i}': request.form.get(f'layer_{i}') for i in range(1, 7)}
    selections['layer_7_text'] = desc_layer_7
    return render_template(
        'result.html',
        full_code_dashed=full_code_dashed,
        full_code_no_dash=full_code_no_dash,
        full_description=full_description,
        is_duplicate=is_duplicate,
        start_tour=start_tour_on_result
    )

@app.route('/save_code', methods=['POST'])
@login_required
def save_code():
    full_code, full_description = request.form.get('full_code'), request.form.get('full_description'); db = get_db()
    try:
        cursor = db.execute("INSERT INTO generated_products (full_code, full_description) VALUES (?, ?)", (full_code, full_description)); db.commit();
        log_activity(f"کد جدید '{full_code}' را ثبت کرد.", cursor.lastrowid)
    except sqlite3.IntegrityError: pass
    if request.form.get('start_tour_on_view') == 'true':
        return redirect(url_for('view_codes', tour='true'))
    return redirect(url_for('view_codes'))

@app.route('/delete_code/<int:code_id>', methods=['POST'])
@admin_required
def delete_code(code_id):
    db = get_db()
    code_to_delete = db.execute("SELECT full_code FROM generated_products WHERE id = ?", (code_id,)).fetchone()

    if code_to_delete:
        db.execute("DELETE FROM generated_products WHERE id = ?", (code_id,))
        db.commit()
        log_activity(f"کد ثبت شده '{code_to_delete['full_code']}' را حذف کرد.", code_id)
        # NEW: Add a success flash message
        flash(f"کد «{code_to_delete['full_code']}» با موفقیت حذف شد.", 'success')
    else:
        # NEW: Add an error flash message if the code wasn't found
        flash('خطا: کد مورد نظر برای حذف یافت نشد.', 'danger')

    return redirect(url_for('view_codes'))

@app.route('/edit_code/<int:code_id>', methods=['GET', 'POST'])
@admin_required
def edit_code(code_id):
    db = get_db(); code = db.execute("SELECT * FROM generated_products WHERE id = ?", (code_id,)).fetchone()
    if not code: flash('کد مورد نظر یافت نشد.', 'danger'); return redirect(url_for('view_codes'))
    if request.method == 'POST':
        new_description = request.form.get('full_description').strip()
        if not new_description: flash('شرح کامل نمی‌تواند خالی باشد.', 'danger'); return render_template('edit_code.html', code=code)
        old_description = code['full_description']
        db.execute("UPDATE generated_products SET full_description = ? WHERE id = ?", (new_description, code_id)); db.commit()
        log_activity(f"شرح کد '{code['full_code']}' را از '{old_description}' به '{new_description}' تغییر داد.", code_id)
        flash('شرح کد با موفقیت به‌روزرسانی شد.', 'success')
        return redirect(url_for('view_codes'))
    return render_template('edit_code.html', code=code)

@app.route('/export/csv')
@login_required
def export_csv():
    df = pd.read_sql_query("SELECT full_code AS 'کد کامل', full_description AS 'شرح کامل', created_at AS 'تاریخ ثبت' FROM generated_products ORDER BY created_at DESC", get_db()); output = io.BytesIO(); df.to_csv(output, index=False, encoding='utf-8-sig'); output.seek(0); response = make_response(output.getvalue()); response.headers["Content-Disposition"] = "attachment; filename=HaniMotor_Exported_Codes.csv"; response.headers["Content-type"] = "text/csv; charset=utf-8"
    return response

@app.route('/print_codes')
@login_required
def print_codes():
    db = get_db()

    # Get all filter parameters from the URL
    search_term = request.args.get('search', '')
    class_filter = request.args.get('class_code', '')
    start_date_jalali = request.args.get('start_date', '')
    end_date_jalali = request.args.get('end_date', '')

    # Reuse the same query logic as the view_codes function
    base_query = "FROM generated_products"
    where_clauses, params = [], []

    if search_term:
        where_clauses.append("(full_code LIKE ? OR full_description LIKE ?)")
        params.extend([f"%{search_term}%", f"%{search_term}%"])
    if class_filter:
        where_clauses.append("full_code LIKE ?")
        params.append(f"{class_filter}-%")
    if start_date_jalali:
        try:
            where_clauses.append("date(created_at) >= ?")
            params.append(jdatetime.datetime.strptime(start_date_jalali, '%Y/%m/%d').togregorian().strftime('%Y-%m-%d'))
        except (ValueError, TypeError): pass
    if end_date_jalali:
        try:
            where_clauses.append("date(created_at) <= ?")
            params.append(jdatetime.datetime.strptime(end_date_jalali, '%Y/%m/%d').togregorian().strftime('%Y-%m-%d'))
        except (ValueError, TypeError): pass

    if where_clauses:
        base_query += " WHERE " + " AND ".join(where_clauses)

    # Fetch ALL matching codes, WITHOUT pagination (LIMIT/OFFSET)
    all_filtered_codes = db.execute("SELECT * " + base_query + " ORDER BY created_at DESC", params).fetchall()

    # Get class description for the report title
    class_description = ""
    if class_filter:
        class_info = db.execute("SELECT description FROM coding_structure WHERE code = ? AND layer_level = 1", (class_filter,)).fetchone()
        if class_info:
            class_description = class_info['description']

    # Prepare filter info to display on the print page
    filters_for_print = {
        'search': search_term, 
        'class_description': class_description, 
        'start_date': start_date_jalali, 
        'end_date': end_date_jalali
    }

    # Render the new print-specific template
    return render_template('print_view.html', codes=all_filtered_codes, filters=filters_for_print)

@app.route('/activity_log')
@admin_required
def activity_log():
    db = get_db()
    page = request.args.get('page', 1, type=int)
    # جدید: دریافت فیلتر نام کاربری از URL
    user_filter = request.args.get('user_filter', '')
    per_page = 20

    # ساخت کوئری پایه و پارامترها
    base_query = "FROM activity_log"
    where_clauses = []
    params = []

    # اگر نام کاربری برای فیلتر انتخاب شده بود، به کوئری اضافه کن
    if user_filter:
        where_clauses.append("username = ?")
        params.append(user_filter)

    if where_clauses:
        base_query += " WHERE " + " AND ".join(where_clauses)

    # شمارش کل لاگ‌ها بر اساس فیلتر برای صفحه‌بندی صحیح
    total_logs = db.execute("SELECT COUNT(id) " + base_query, params).fetchone()[0]
    total_pages = math.ceil(total_logs / per_page)

    offset = (page - 1) * per_page
    
    # کپی کردن پارامترها برای کوئری نهایی و اضافه کردن limit/offset
    final_params = list(params)
    final_params.extend([per_page, offset])

    logs_on_page = db.execute(
        "SELECT * " + base_query + " ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        final_params
    ).fetchall()

    # جدید: دریافت لیست تمام کاربران برای نمایش در منوی کشویی
    all_users = db.execute("SELECT DISTINCT username FROM users WHERE username IS NOT NULL ORDER BY username").fetchall()

    return render_template(
        'activity_log.html',
        logs=logs_on_page,
        page=page,
        total_pages=total_pages,
        total_logs=total_logs,
        all_users=all_users,  # ارسال لیست کاربران به قالب
        user_filter=user_filter # ارسال نام کاربری فیلتر شده برای نمایش در منو
    )

# =================== START OF CHANGED/NEW SECTIONS ===================

@app.route('/manage_parameters')
@admin_required
def manage_parameters():
    db = get_db()
    # CHANGE: Load only root items for a fast initial page load.
    root_items_raw = db.execute("""
        SELECT *, (EXISTS (SELECT 1 FROM coding_structure AS sub WHERE sub.parent_id = main.id)) AS has_children
        FROM coding_structure AS main
        WHERE parent_id IS NULL
        ORDER BY code
    """).fetchall()
    root_items = [dict(row) for row in root_items_raw]
    return render_template('manage_parameters.html', root_items=root_items)

# Don't forget to import json at the top of your main.py if it's not already there
import json

# ... (the rest of your main.py file)

@app.route('/import_parameters', methods=['GET', 'POST'])
@admin_required
def import_parameters():
    if request.method == 'POST':
        if 'csv_file' not in request.files or not request.files['csv_file'].filename:
            flash('هیچ فایلی انتخاب نشده است.', 'danger'); return redirect(request.url)

        file = request.files['csv_file']
        if not (file and file.filename.endswith('.csv')):
            flash('فرمت فایل باید CSV باشد.', 'danger'); return redirect(request.url)

        try:
            stream = io.StringIO(file.stream.read().decode("utf-8-sig"), newline=None)
            df = pd.read_csv(stream, header=None, dtype=str)
            db = get_db()
            added_count = 0

            # Data structures for the final report
            additions_summary = {}
            # NEW: A list to keep track of skipped (duplicate) items
            skipped_items = []

            for index, row in df.iterrows():
                parent_id = None
                parent_description = "شاخه اصلی"
                current_class_name = None

                num_columns = len(row.dropna())
                is_full_format = num_columns % 2 != 0
                effective_columns = num_columns - 1 if is_full_format else num_columns

                for i in range(0, effective_columns, 2):
                    description = row.iloc[i]
                    code = row.iloc[i + 1]
                    layer_level = (i // 2) + 1

                    if pd.isna(description) or not str(description).strip(): continue
                    description = str(description).strip()

                    if layer_level == 1:
                        current_class_name = description

                    existing_item = db.execute(
                        "SELECT id, description FROM coding_structure WHERE description = ? AND layer_level = ? AND (parent_id = ? OR (parent_id IS NULL AND ? IS NULL))",
                        (description, layer_level, parent_id, parent_id)
                    ).fetchone()

                    if existing_item:
                        # CHANGE: If item exists, add it to the skipped list and continue
                        skipped_items.append(f"«{description}» در شاخه «{parent_description}»")
                        parent_id = existing_item['id']
                        parent_description = existing_item['description']
                    else:
                        # Logic for adding a new item (remains the same)
                        if not current_class_name:
                            current_class_name = "سایر کلاس‌ها"

                        if current_class_name not in additions_summary:
                            additions_summary[current_class_name] = {}

                        target_parent = parent_description if parent_description != "شاخه اصلی" else "سطح اصلی کلاس"
                        additions_summary[current_class_name][target_parent] = additions_summary[current_class_name].get(target_parent, 0) + 1
                        added_count += 1

                        # ... (code generation logic remains the same) ...
                        if pd.isna(code) or not str(code).strip():
                            max_code_row = db.execute("SELECT MAX(CAST(code AS INTEGER)) FROM coding_structure WHERE layer_level = ? AND (parent_id = ? OR (parent_id IS NULL AND ? is NULL))", (layer_level, parent_id, parent_id)).fetchone()
                            new_code_num = (max_code_row[0] or 0) + 1
                            code_lengths = {1: 2, 2: 1, 3: 2, 4: 2, 5: 3, 6: 2, 7: 3}
                            final_code = str(new_code_num).zfill(code_lengths.get(layer_level, 3))
                        else:
                            final_code = str(code).strip()

                        cursor = db.execute("INSERT INTO coding_structure (layer_level, code, description, parent_id) VALUES (?, ?, ?, ?)",
                                          (layer_level, final_code, description, parent_id))
                        parent_id = cursor.lastrowid
                        parent_description = description

            db.commit()

            # --- CHANGE: Build the final report including skipped items ---

            # Build summary for added items
            added_summary_html = ""
            if additions_summary:
                class_details_html = ""
                for class_name, sub_additions in additions_summary.items():
                    sub_details_html = "".join([f"<li>{count} مورد به «{parent}»</li>" for parent, count in sub_additions.items()])
                    class_details_html += f"<li><b>در کلاس «{class_name}»:</b><ul>{sub_details_html}</ul></li>"
                added_summary_html = f"<br><b>موارد جدید اضافه شده:</b><ul>{class_details_html}</ul>"

            # NEW: Build summary for skipped items
            skipped_summary_html = ""
            # To show unique items, we convert the list to a set and back
            unique_skipped = sorted(list(set(skipped_items))) 
            if unique_skipped:
                details = "".join([f"<li>{item} از قبل وجود داشت.</li>" for item in unique_skipped])
                skipped_summary_html = f"<br><b>موارد تکراری (نادیده گرفته شدند):</b><ul>{details}</ul>"

            final_message = Markup(f"عملیات با موفقیت انجام شد. <strong>{added_count}</strong> پارامتر جدید اضافه شد.{added_summary_html}{skipped_summary_html}")
            log_activity(f"ورود دسته‌جمعی: {added_count} آیتم جدید اضافه شد، {len(unique_skipped)} مورد تکراری نادیده گرفته شد.")
            flash(final_message, 'success')
            return redirect(url_for('manage_parameters'))

        except IndexError:
             db.rollback()
             flash(f"خطا در پردازش فایل: تعداد ستون‌ها در یکی از ردیف‌ها فرد است و با فرمت (شرح, کد) سازگار نیست.", 'danger')
             return redirect(request.url)
        except Exception as e:
            db.rollback()
            flash(f"خطا در پردازش فایل: {e}", 'danger')
            return redirect(request.url)

    return render_template('import_parameters.html')

# --- Original API Routes (UNCHANGED) ---
@app.route('/api/get_children/<int:parent_id>')
@login_required
def get_children(parent_id):
    items = get_db().execute("SELECT * FROM coding_structure WHERE parent_id = ? AND is_archived = 0 ORDER BY code", (parent_id,)).fetchall()
    return jsonify([dict(row) for row in items])

@app.route('/api/get_suggestions/<int:level>/<parent_id_str>')
@login_required
def get_suggestions(level, parent_id_str):
    db = get_db()
    if parent_id_str == 'null': rows = db.execute("SELECT DISTINCT description FROM coding_structure WHERE layer_level = 1 AND is_archived = 0 ORDER BY description").fetchall()
    else:
        parent_id = int(parent_id_str)
        query = "SELECT DISTINCT T2.description FROM coding_structure AS T1 JOIN coding_structure AS T2 ON T1.id = T2.parent_id WHERE T1.parent_id = (SELECT parent_id FROM coding_structure WHERE id = ?) AND T2.layer_level = ? AND T2.is_archived = 0 ORDER BY T2.description"
        rows = db.execute(query, (parent_id, level)).fetchall()
    return jsonify([row['description'] for row in rows])

@app.route('/api/add_item', methods=['POST'])
@admin_required
def add_item():
    data = request.json; description = data.get('description').strip(); layer_level, parent_id = data.get('layer_level'), data.get('parent_id'); db = get_db(); parent_id_check = parent_id if parent_id is not None else -1
    if db.execute("SELECT id FROM coding_structure WHERE description = ? AND layer_level = ? AND (parent_id = ? OR (parent_id IS NULL AND ? = -1))", (description, layer_level, parent_id, parent_id_check)).fetchone(): return jsonify({'success': False, 'message': f'خطا: آیتمی با نام "{description}" از قبل برای این والد وجود دارد.'}), 400
    max_code_row = db.execute("SELECT MAX(CAST(code AS INTEGER)) FROM coding_structure WHERE layer_level = ? AND (parent_id = ? OR (parent_id IS NULL AND ? = -1))", (layer_level, parent_id, parent_id_check)).fetchone(); new_code_num = (max_code_row[0] or 0) + 1; code_lengths = {1: 2, 2: 1, 3: 2, 4: 2, 5: 3, 6: 2, 7: 3}; new_code = str(new_code_num).zfill(code_lengths.get(layer_level, 3))
    try:
        cursor = db.execute("INSERT INTO coding_structure (layer_level, code, description, parent_id) VALUES (?, ?, ?, ?)", (layer_level, new_code, description, parent_id)); db.commit(); log_activity(f"پارامتر جدید '{description}' را اضافه کرد.", cursor.lastrowid)
        return jsonify({'success': True, 'item': {'id': cursor.lastrowid, 'code': new_code, 'description': description}})
    except sqlite3.Error as e: db.rollback(); return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/update_item_description', methods=['POST'])
@admin_required
def update_item_description():
    data = request.json; item_id, new_description = data.get('id'), data.get('description').strip()
    if not all([item_id, new_description]): return jsonify({'success': False, 'message': 'اطلاعات ناقص است.'}), 400
    db = get_db()
    try:
        old_desc = db.execute("SELECT description FROM coding_structure WHERE id = ?", (item_id,)).fetchone()['description']; db.execute("UPDATE coding_structure SET description = ? WHERE id = ?", (new_description, item_id)); db.commit(); log_activity(f"نام پارامتر '{old_desc}' را به '{new_description}' تغییر داد.", item_id)
        return jsonify({'success': True, 'message': 'پارامتر با موفقیت به‌روزرسانی شد.'})
    except sqlite3.Error as e: db.rollback(); return jsonify({'success': False, 'message': f'خطا در دیتابیس: {e}'}), 500

@app.route('/toggle_archive_parameter/<int:item_id>/<int:status>', methods=['POST'])
@admin_required
def toggle_archive_parameter(item_id, status):
    db = get_db(); new_status = 1 if status == 0 else 0
    item_to_log = db.execute("SELECT description FROM coding_structure WHERE id = ?", (item_id,)).fetchone()
    if not item_to_log: flash('آیتم مورد نظر یافت نشد.', 'danger'); return redirect(url_for('manage_parameters'))
    item_description = item_to_log['description']
    ids_to_toggle, parent_queue = [item_id], [item_id]
    while parent_queue:
        children = db.execute("SELECT id FROM coding_structure WHERE parent_id = ?", (parent_queue.pop(0),)).fetchall()
        for child in children: ids_to_toggle.append(child['id']); parent_queue.append(child['id'])
    placeholders = ', '.join('?' for _ in ids_to_toggle)
    try:
        db.execute(f"UPDATE coding_structure SET is_archived = ? WHERE id IN ({placeholders})", [new_status] + ids_to_toggle); db.commit()
        action_verb = "آرشیو" if new_status == 1 else "بازیابی"
        log_activity(f"پارامتر '{item_description}' و زیرمجموعه‌های آن را {action_verb} کرد.", item_id)
        flash_message = Markup(f"پارامتر <strong>{item_description}</strong> و زیرمجموعه‌های آن با موفقیت {action_verb} شدند.")
        flash(flash_message, 'success')
    except sqlite3.Error as e: db.rollback(); flash(f'خطا در عملیات آرشیو: {e}', 'danger')
    return redirect(url_for('manage_parameters'))

# --- NEW API Routes for the Hybrid Parameter Management Page ---

@app.route('/api/get_parameter_children/<int:parent_id>')
@login_required
def get_parameter_children(parent_id):
    db = get_db()
    children_raw = db.execute("""
        SELECT *, (EXISTS (SELECT 1 FROM coding_structure AS sub WHERE sub.parent_id = main.id)) AS has_children
        FROM coding_structure AS main
        WHERE parent_id = ?
        ORDER BY code
    """, (parent_id,)).fetchall()
    return jsonify([dict(row) for row in children_raw])

@app.route('/api/search_parameters')
@login_required
def search_parameters():
    term = request.args.get('term', '').strip()
    if not term:
        return jsonify([])

    db = get_db()
    query = """
    WITH RECURSIVE
      search_matches AS (
        SELECT * FROM coding_structure WHERE description LIKE ?
      ),
      full_context AS (
        SELECT * FROM search_matches
        UNION
        SELECT cs.* FROM coding_structure cs JOIN full_context fc ON cs.id = fc.parent_id
      )
    SELECT DISTINCT 
           id, code, description, layer_level, parent_id, is_archived,
           (EXISTS (SELECT 1 FROM coding_structure AS sub WHERE sub.parent_id = main.id)) AS has_children
    FROM full_context AS main
    ORDER BY layer_level, code
    """
    results_raw = db.execute(query, (f'%{term}%',)).fetchall()
    return jsonify([dict(row) for row in results_raw])

# --- NEW ROUTE FOR VIEWING SAVED CODE DETAILS ---
@app.route('/code_details/<int:code_id>')
@login_required
def code_details(code_id):
    db = get_db()
    code = db.execute("SELECT * FROM generated_products WHERE id = ?", (code_id,)).fetchone()

    if not code:
        flash('کد مورد نظر یافت نشد.', 'danger')
        return redirect(url_for('view_codes'))

    # Prepare variables needed by result.html template
    full_code_dashed = code['full_code']
    full_code_no_dash = code['full_code'].replace('-', '')
    full_description = code['full_description']

    # Pass a special flag to the template to indicate this is an existing code
    return render_template(
        'result.html',
        full_code_dashed=full_code_dashed,
        full_code_no_dash=full_code_no_dash,
        full_description=full_description,
        is_existing_code=True  # This new flag will hide "Save" and "Back" buttons
    )

@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    # این تابع دیگر صفحه جداگانه ندارد و فقط درخواست را پردازش می‌کند
    username = request.form.get('username')
    db = get_db()
    user = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()

    if user:
        message = f"کاربر '{username}' درخواست بازنشانی رمز عبور دارد."
        link = url_for('manage_users') # لینک به صفحه مدیریت کاربران

        db.execute(
            "INSERT INTO notifications (user_id, message, link) VALUES (?, ?, ?)",
            (user['id'], message, link)
        )
        db.commit()
        log_activity(f"کاربر '{username}' درخواست فراموشی رمز عبور ثبت کرد.")
        # پیغام موفقیت در اینجا به کاربر نمایش داده می‌شود
        flash('درخواست شما برای ادمین سیستم ارسال شد.', 'success')
    else:
        flash('کاربری با این نام یافت نشد.', 'danger')

    return redirect(url_for('login'))

@app.route('/api/notifications')
@admin_required
def get_notifications():
    db = get_db()
    notifications = db.execute(
        "SELECT * FROM notifications WHERE is_read = 0 ORDER BY created_at DESC LIMIT 10"
    ).fetchall()
    return jsonify([dict(row) for row in notifications])

@app.route('/api/notifications/mark_read', methods=['POST'])
@admin_required
def mark_notifications_read():
    db = get_db()
    db.execute("UPDATE notifications SET is_read = 1 WHERE is_read = 0")
    db.commit()
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=81, debug=True)