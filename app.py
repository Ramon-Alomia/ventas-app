import os
from functools import wraps
from datetime import timedelta
from requests.exceptions import SSLError, RequestException
import requests
import psycopg2
from flask import (
    Flask, render_template, request, redirect,
    session, url_for, flash, abort
)
from psycopg2.extras import RealDictCursor
from flask_talisman import Talisman
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError, InvalidHashError
import logging

# Se define ruta base para archivos de certificado
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Decorador para controlar acceso por roles
def roles_required(*permitted_roles):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if session.get("role") not in permitted_roles:
                return abort(403)
            return f(*args, **kwargs)
        return wrapped
    return decorator

# Configuración de Argon2id para hashing de contraseñas
ph = PasswordHasher(
    time_cost=2,
    memory_cost=102400,
    parallelism=8,
    hash_len=32,
    salt_len=16,
    type=Type.ID
)

# Inicialización de Flask
app = Flask(__name__)
# Logging en DEBUG
logging.basicConfig(level=logging.DEBUG)
app.logger.setLevel(logging.DEBUG)

# Configuración de cookies seguras
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)
app.permanent_session_lifetime = timedelta(minutes=30)

# Políticas de seguridad CSP y HSTS
csp = {
  'default-src': ["'self'"],
  'script-src':  ["'self'", 'cdnjs.cloudflare.com'],
  'style-src':   ["'self'", "'unsafe-inline'", 'cdnjs.cloudflare.com', 'fonts.googleapis.com'],
  'font-src':    ["'self'", 'fonts.gstatic.com'],
  'img-src':     ["'self'", 'data:']
}
Talisman(
    app,
    content_security_policy=csp,
    force_https=True,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000
)

@app.after_request
def apply_secure_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer-when-downgrade'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# SECRET_KEY desde environment
tmp_secret = os.getenv("SECRET_KEY")
if not tmp_secret:
    raise RuntimeError("SECRET_KEY no está configurada en las Environment Variables")
app.secret_key = tmp_secret

# Configuración Service Layer SAP
SERVICE_LAYER_URL = os.getenv(
    "SERVICE_LAYER_URL",
    "https://hwvdvsbo04.virtualdv.cloud:50000/b1s/v1"
).rstrip("/")
COMPANY_DB  = os.getenv("COMPANY_DB", "PRDBERSA")
SL_USER     = os.getenv("SL_USER", "brsuser02")
SL_PASSWORD = os.getenv("SL_PASSWORD", "$PniBvQ7rBa6!A")

# Conexión a PostgreSQL
def get_db_connection():
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        raise RuntimeError("DATABASE_URL no está configurada en las Environment Variables")
    return psycopg2.connect(db_url, sslmode='require', cursor_factory=RealDictCursor)

# Rutas de la aplicación
@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        user = request.form.get("username")
        pwd  = request.form.get("password")
        conn = get_db_connection(); cur = conn.cursor()
        cur.execute(
            "SELECT username, password AS hashed, role"
            " FROM users WHERE username=%s AND active=TRUE", (user,)
        )
        row = cur.fetchone()
        if row:
            try:
                ph.verify(row['hashed'], pwd)
            except (InvalidHashError, VerifyMismatchError):
                error = "Credenciales inválidas."
            else:
                if ph.check_needs_rehash(row['hashed']):
                    new_hash = ph.hash(pwd)
                    cur.execute(
                        "UPDATE users SET password=%s WHERE username=%s",
                        (new_hash, user)
                    )
                    conn.commit()
                session.permanent    = True
                session['username']  = row['username']
                session['role']      = row['role']
                # Obtener almacenes del usuario
                cur.execute(
                    "SELECT whscode FROM user_warehouses WHERE username=%s",
                    (user,)
                )
                whs = cur.fetchall()
                session['warehouses'] = [w['whscode'] for w in whs]
                # Obtener cardcode del primer almacén
                if whs:
                    cur.execute(
                        "SELECT cardcode FROM warehouses WHERE whscode=%s",
                        (whs[0]['whscode'],)
                    )
                    w = cur.fetchone()
                    session['cardcode'] = w['cardcode'] if w else None
                else:
                    session['cardcode'] = None
                cur.close(); conn.close()
                return redirect(url_for('dashboard'))
        else:
            error = "Credenciales inválidas."
        cur.close(); conn.close()
    return render_template('login.html', error=error)

@app.route("/dashboard")
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT itemcode, description FROM items_map")
    items = cur.fetchall()
    cur.close(); conn.close()
    # Envia también la lista de almacenes desde sesión
    return render_template(
        'dashboard.html',
        username=session['username'],
        items=items,
        warehouses=session.get('warehouses', []),
        role=session.get('role')
    )

@app.route("/submit", methods=["POST"])
def submit():
    if 'username' not in session:
        return redirect(url_for('login'))

    date = request.form.get('date')
    if not date:
        flash('Por favor selecciona una fecha para la orden.', 'error')
        return redirect(url_for('dashboard'))

    # Construcción de líneas
    # 1) obtener almacén seleccionado (o por defecto)
    selected_whs = request.form.get('warehouse', session['warehouses'][0])
    # 2) obtener cardcode para ese almacén
    conn_db = get_db_connection(); cur_db = conn_db.cursor()
    cur_db.execute(
        "SELECT cardcode FROM warehouses WHERE whscode=%s",
        (selected_whs,)
    )
    row = cur_db.fetchone()
    conn_db.close()
    cardcode = row['cardcode'] if row and row.get('cardcode') else session.get('cardcode')

    # construcción de líneas usando selected_whs
    lines = []
    for code, qty in zip(request.form.getlist('item_code'), request.form.getlist('quantity')):
        try:
            qty_int = int(qty)
        except ValueError:
            continue
        if qty_int > 0:
            lines.append({
                'ItemCode': code,
                'Quantity': qty_int,
                'WarehouseCode': selected_whs
            })

    order = {
        'CardCode':      cardcode,
        'DocDate':       date,
        'DocDueDate':    date,
        'DocumentLines': lines
    }

    order = {'CardCode': session.get('cardcode'), 'DocDate': date, 'DocDueDate': date, 'DocumentLines': lines}

    try:
        # 1) Sesión híbrida: requests.Session
        sl = requests.Session()
        sl.verify = False
        sl.headers.update({'Content-Type':'application/json', 'Accept':'application/json'})

        # Login
        auth = sl.post(f"{SERVICE_LAYER_URL}/Login", json={
            'CompanyDB': COMPANY_DB, 'UserName': SL_USER, 'Password': SL_PASSWORD
        })
        auth.raise_for_status()

        # 2) Reset jar y set cookie con path
        sid   = auth.json().get('SessionId')
        route = auth.cookies.get('ROUTEID')
        sl.cookies.clear()
        sl.cookies.set('B1SESSION', sid, path='/b1s/v1')
        if route:
            sl.cookies.set('ROUTEID', route, path='/')
        app.logger.debug('Jar reseteado: %s', sl.cookies.get_dict())

        # 3) Metadata debug
        meta = sl.get(f"{SERVICE_LAYER_URL}/$metadata")
        app.logger.debug('Metadata Orders snippet: %s', meta.text[:300])

        # 4) Envío de la orden
        sl.headers.update({'Prefer':'return=representation'})
        resp = sl.post(f"{SERVICE_LAYER_URL}/Orders", json=order)
        app.logger.debug('Response POST Orders %s — %s', resp.status_code, resp.text[:300])
        resp.raise_for_status()

    except SSLError as e:
        app.logger.error(f"SSL error al conectar con SAP: {e}", exc_info=True)
        flash(f"SSL error detallado: {e}", 'error')
        return redirect(url_for('dashboard'))
    except RequestException as e:
        app.logger.error(f"Error conectando con SAP: {e}", exc_info=True)
        flash(f"Error conectando con SAP: {e}", 'error')
        return redirect(url_for('dashboard'))

    # Guardar histórico y renderizar
    # Guardar histórico con selected_whs y cardcode calculado
    data = resp.json()
    conn_h = get_db_connection(); cur_h = conn_h.cursor()
    for line in lines:
        cur_h.execute(
            """
            INSERT INTO recorded_orders (
              timestamp, username, whscode, cardcode, docentry, docnum, itemcode, quantity
            ) VALUES (
              NOW(), %s, %s, %s, %s, %s, %s, %s
            )
            """,
            (
                session['username'],
                selected_whs,
                cardcode,
                data.get('DocEntry'),
                data.get('DocNum'),
                line['ItemCode'],
                line['Quantity']
            )
        )
    conn_h.commit(); cur_h.close(); conn_h.close()
    return render_template(
        'result.html',
        success=True,
        docnum=data.get('DocNum'),
        docentry=data.get('DocEntry')
    )

@app.route("/history")
def history():
    if 'username' not in session:
        return redirect(url_for('login'))
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    codex/update-order-history-view-format-zxh0vb
    whscode = request.args.getlist('whscode')
    user_filter = request.args.getlist('username')

main
    conn = get_db_connection(); cur = conn.cursor()
    allowed = ('manager','admin','supervisor')
    query = (
        "SELECT timestamp, username, cardcode, whscode, docnum, itemcode, quantity "
        "FROM recorded_orders WHERE 1=1"
    )
    params = []
    if session.get('role') in allowed:
        if user_filter:
    codex/update-order-history-view-format-zxh0vb
            query += " AND username = ANY(%s)"
main
            params.append(user_filter)
    else:
        query += " AND username=%s"
        params.append(session['username'])
    if start_date:
        query += " AND timestamp::date >= %s"
        params.append(start_date)
    if end_date:
        query += " AND timestamp::date <= %s"
        params.append(end_date)
    if whscode:
   codex/update-order-history-view-format-zxh0vb
        query += " AND whscode = ANY(%s)"
        params.append(whscode)
    query += " ORDER BY timestamp DESC LIMIT 100"
    cur.execute(query, params)
    rows = cur.fetchall()
    cur.execute("SELECT whscode FROM warehouses ORDER BY whscode")
    warehouses = [r['whscode'] for r in cur.fetchall()]
    users_options = []
    if session.get('role') in allowed:
        cur.execute("SELECT username FROM users WHERE active=TRUE ORDER BY username")
        users_options = [r['username'] for r in cur.fetchall()]
    cur.close(); conn.close()
    filters = {'start_date': start_date, 'end_date': end_date, 'whscode': whscode, 'username': user_filter}
    return render_template('history.html', rows=rows, filters=filters, is_admin=session.get('role') in allowed,
                           warehouses=warehouses, users_options=users_options)
main

@app.route("/admin", methods=["GET", "POST"])
@roles_required('admin')
def admin():
    if 'username' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection(); cur = conn.cursor()
    if request.method == 'POST':
        form_type = request.form.get('form_type')
        if form_type == 'add_user':
            username = request.form.get('username')
            password = request.form.get('password')
            role = request.form.get('role', 'user')
            warehouses = [w.strip() for w in request.form.get('warehouses', '').split(',') if w.strip()]
            hashed = ph.hash(password)
            cur.execute(
                "INSERT INTO users (username, password, role, active) VALUES (%s, %s, %s, TRUE)",
                (username, hashed, role)
            )
            for wh in warehouses:
                cur.execute(
                    "INSERT INTO user_warehouses (username, whscode) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                    (username, wh)
                )
            conn.commit()
        elif form_type == 'toggle_user':
            username = request.form.get('username')
            cur.execute("UPDATE users SET active = NOT active WHERE username=%s", (username,))
            conn.commit()
        elif form_type == 'update_user_wh':
            username = request.form.get('username')
            warehouses = [w.strip() for w in request.form.get('warehouses', '').split(',') if w.strip()]
            cur.execute("DELETE FROM user_warehouses WHERE username=%s", (username,))
            for wh in warehouses:
                cur.execute(
                    "INSERT INTO user_warehouses (username, whscode) VALUES (%s, %s)",
                    (username, wh)
                )
            conn.commit()
        elif form_type == 'add_wh':
            whscode  = request.form.get('whscode')
            cardcode = request.form.get('cardcode')
            whsdesc  = request.form.get('whsdesc')
            cur.execute(
                """
                INSERT INTO warehouses (whscode, cardcode, whsdesc)
                VALUES (%s, %s, %s)
                ON CONFLICT (whscode) DO UPDATE
                SET cardcode=EXCLUDED.cardcode, whsdesc=EXCLUDED.whsdesc
                """,
                (whscode, cardcode, whsdesc)
            )
            conn.commit()
        elif form_type == 'delete_wh':
            whscode = request.form.get('whscode')
            cur.execute("DELETE FROM user_warehouses WHERE whscode=%s", (whscode,))
            cur.execute("DELETE FROM warehouses WHERE whscode=%s", (whscode,))
            conn.commit()

    cur.execute("SELECT username, role, active FROM users ORDER BY username")
    users = cur.fetchall()
    for u in users:
        cur.execute("SELECT whscode FROM user_warehouses WHERE username=%s", (u['username'],))
        whs = cur.fetchall()
        u['warehouses'] = [w['whscode'] for w in whs]
    cur.execute("SELECT whscode, cardcode, whsdesc FROM warehouses ORDER BY whscode")
    warehouses = cur.fetchall()
    cur.close(); conn.close()
    return render_template('admin.html', users=users, warehouses=warehouses)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login'))

# Migración de contraseñas a Argon2id
def migrate_passwords():
    conn = get_db_connection(); cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT username, password FROM users WHERE active=TRUE")
    users = cur.fetchall()
    for u in users:
        new_h = ph.hash(u['password'])
        cur.execute("UPDATE users SET password=%s WHERE username=%s", (new_h, u['username']))
    conn.commit(); cur.close(); conn.close(); print(f"Migrados {len(users)} usuarios.")

if __name__ == "__main__":
    if os.getenv('MIGRATE')=='1':
        migrate_passwords()
    else:
        app.run(debug=False, host='0.0.0.0', port=int(os.getenv('PORT',5000)), ssl_context='adhoc')