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
import logging
logging.basicConfig(level=logging.DEBUG)
app.logger.setLevel(logging.DEBUG)

# Cookies seguras y sesiones
a = {
    'SESSION_COOKIE_SECURE': True,
    'SESSION_COOKIE_HTTPONLY': True,
    'SESSION_COOKIE_SAMESITE': 'Lax'
}
app.config.update(a)
app.permanent_session_lifetime = timedelta(minutes=30)

# Políticas CSP y HSTS
csp = {
  'default-src': ["'self'"],
  'script-src':  ["'self'", 'cdnjs.cloudflare.com'],
  'style-src':   ["'self'", "'unsafe-inline'", 'fonts.googleapis.com'],
  'font-src':    ["'self'", 'fonts.gstatic.com'],
  'img-src':     ["'self'", 'data:']
}
Talisman(app, content_security_policy=csp)

@app.after_request
def apply_secure_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer-when-downgrade'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# SECRET_KEY
tmp_secret = os.getenv("SECRET_KEY")
if not tmp_secret:
    raise RuntimeError("SECRET_KEY no está configurada")
app.secret_key = tmp_secret

# Service Layer SAP
SERVICE_LAYER_URL = os.getenv(
    "SERVICE_LAYER_URL",
    "https://hwvdvsbo04.virtualdv.cloud:50000/b1s/v1"
).rstrip("/")
COMPANY_DB  = os.getenv("COMPANY_DB", "PRDBERSA")
SL_USER     = os.getenv("SL_USER", "brsuser02")
SL_PASSWORD = os.getenv("SL_PASSWORD", "\$PniBvQ7rBa6!A")

# Conexión Postgres
def get_db_connection():
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        raise RuntimeError("DATABASE_URL no está configurada")
    return psycopg2.connect(db_url, sslmode='require', cursor_factory=RealDictCursor)

# --- Rutas básicas ---
@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        user = request.form['username']
        pwd  = request.form['password']
        conn = get_db_connection(); cur = conn.cursor()
        cur.execute("SELECT username, password, role FROM users WHERE username=%s AND active=TRUE", (user,))
        row = cur.fetchone()
        cur.close(); conn.close()
        if row:
            try:
                ph.verify(row[1], pwd)
            except (InvalidHashError, VerifyMismatchError):
                error = "Credenciales inválidas."
            else:
                session.permanent = True
                session['username'] = row[0]
                session['role']     = row[2]
                return redirect(url_for('dashboard'))
        else:
            error = "Credenciales inválidas."
    return render_template('login.html', error=error)

@app.route("/dashboard")
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT itemcode, description FROM items_map")
    items = cur.fetchall()
    cur.close(); conn.close()
    return render_template('dashboard.html', username=session['username'], items=items)

# --- Envío de órdenes ---
@app.route("/submit", methods=["POST"])
def submit():
    if 'username' not in session:
        return redirect(url_for('login'))
    date = request.form.get('date')
    if not date:
        flash('Por favor selecciona una fecha', 'error')
        return redirect(url_for('dashboard'))

    lines = []
    for code, qty in zip(request.form.getlist('item_code'), request.form.getlist('quantity')):
        try:
            if int(qty) > 0:
                lines.append({'ItemCode': code, 'Quantity': int(qty), 'WarehouseCode': session.get('warehouses', [])[0]})
        except ValueError:
            continue

    order = {
        'CardCode':      session.get('cardcode'),
        'DocDate':       date,
        'DocDueDate':    date,
        'DocumentLines': lines
    }

    try:
        sl = requests.Session()
        sl.verify = False
        sl.headers.update({'Content-Type': 'application/json', 'Accept': 'application/json'})

        # Login SL
        auth = sl.post(f"{SERVICE_LAYER_URL}/Login", json={
            'CompanyDB': COMPANY_DB,
            'UserName':  SL_USER,
            'Password':  SL_PASSWORD
        })
        auth.raise_for_status()
        app.logger.debug("Cookies SL tras login: %s", sl.cookies.get_dict())

        # Debug Metadata & GET Orders
        meta = sl.get(f"{SERVICE_LAYER_URL}/$metadata").text
        app.logger.debug("Metadata Orders EntitySet:\n%s", meta)
        orders_get = sl.get(f"{SERVICE_LAYER_URL}/Orders")
        app.logger.debug("GET Orders: %s", orders_get.status_code)

        # POST /Orders
        sl.headers.update({'Prefer': 'return=representation'})
        resp = sl.post(f"{SERVICE_LAYER_URL}/Orders", json=order)
        app.logger.debug("POST Orders: %s - %s", resp.status_code, resp.text[:200])
        resp.raise_for_status()

    except SSLError as e:
        app.logger.error("SSL error: %s", e, exc_info=True)
        flash(f"SSL error: {e}", 'error')
        return redirect(url_for('dashboard'))
    except RequestException as e:
        app.logger.error("Error SL: %s", e, exc_info=True)
        flash(f"Error conectando con SAP: {e}", 'error')
        return redirect(url_for('dashboard'))

    data = resp.json()
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO recorded_orders (timestamp, username, whscode, cardcode, docentry, docnum)
        VALUES (NOW(), %s, %s, %s, %s, %s)
        """,
        (session['username'], session['warehouses'][0], session.get('cardcode'), data.get('DocEntry'), data.get('DocNum'))
    )
    conn.commit(); cur.close(); conn.close()

    return render_template('result.html', success=True, docnum=data.get('DocNum'), docentry=data.get('DocEntry'))

@app.route("/history")
def history():
    if 'username' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection(); cur = conn.cursor()
    if session.get('role') == 'manager':
        whs = session.get('warehouses', [])
        cur.execute(
            "SELECT timestamp, cardcode, whscode, docnum FROM recorded_orders WHERE whscode = ANY(%s) ORDER BY timestamp DESC",
            (whs,)
        )
    else:
        cur.execute(
            "SELECT timestamp, cardcode, whscode, docnum FROM recorded_orders WHERE username=%s ORDER BY timestamp DESC",
            (session['username'],)
        )
    rows = cur.fetchall(); cur.close(); conn.close()
    return render_template('history.html', rows=rows)

@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)), debug=False)
