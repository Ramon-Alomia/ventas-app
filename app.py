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
    'style-src':   ["'self'", 'cdnjs.cloudflare.com'],
    'img-src':     ["'self'", 'data:' ]
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

@app.route("/submit", methods=["POST"])
def submit():
    if 'username' not in session:
        return redirect(url_for('login'))
    date = request.form.get('date')
    if not date:
        flash('Por favor selecciona una fecha para la orden.', 'error')
        return redirect(url_for('dashboard'))
    # Construcción de las líneas
    lines = []
    for code, qty in zip(
        request.form.getlist('item_code'),
        request.form.getlist('quantity')
    ):
        try:
            qty_int = int(qty)
        except ValueError:
            continue
        if qty_int > 0:
            lines.append({
                'ItemCode':      code,
                'Quantity':      qty_int,
                'WarehouseCode': session['warehouses'][0]
            })
    order = {
        'CardCode':      session.get('cardcode'),
        'DocDate':       date,
        'DocDueDate':    date,
        'DocumentLines': lines
    }
    try:
        # Sesión persistente
        sl = requests.Session()
        sl.verify = True
        sl.headers.update({
            'Content-Type': 'application/json',
            'Accept':       'application/json'
        })
        # Login SL
        auth = sl.post(f"{SERVICE_LAYER_URL}/Login", json={
            'CompanyDB': COMPANY_DB,
            'UserName':  SL_USER,
            'Password':  SL_PASSWORD
        })
        auth.raise_for_status()
        # Debug cookies tras login
        app.logger.debug(f"Cookies SL: {sl.cookies.get_dict()}")
        # Forzar cookie B1SESSION si no está
        sid = auth.json().get('SessionId')
        route = auth.cookies.get('ROUTEID')
        sl.cookies.clear()
        sl.cookies.set('B1SESSION', sid, path='/')
        if route:
            sl.cookies.set('ROUTEID', route, path='/')
        # Debug GET endpoints
        meta_get = sl.get(f"{SERVICE_LAYER_URL}/$metadata")
        app.logger.debug(f"GET $metadata: {meta_get.status_code}")
        orders_get = sl.get(f"{SERVICE_LAYER_URL}/Orders")
        app.logger.debug(f"GET Orders: {orders_get.status_code} body: {orders_get.text[:200]}")
        # POST orden
        sl.headers.update({'Prefer': 'return=representation'})
        resp = sl.post(f"{SERVICE_LAYER_URL}/Orders", json=order)
        resp.raise_for_status()
    except SSLError as e:
        flash(f"SSL error: {e}", 'error')
        return redirect(url_for('dashboard'))
    except RequestException as e:
        flash(f"Error conectando con SAP: {e}", 'error')
        return redirect(url_for('dashboard'))
    # Resultado exitoso
    result = resp.json()
    return render_template('result.html', success=True,
                           docnum=result.get('DocNum'),
                           docentry=result.get('DocEntry'))

# Historial de órdenes
@app.route("/history")
def history():
    if 'username' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection(); cur = conn.cursor()
    if session.get('role') == 'manager':
        whs = session.get('warehouses', [])
        if whs:
            cur.execute(
                "SELECT timestamp, cardcode, whscode, docnum"
                " FROM recorded_orders WHERE whscode = ANY(%s)"
                " ORDER BY timestamp DESC LIMIT 50", (whs,)
            )
            rows = cur.fetchall()
        else:
            rows = []
    else:
        cur.execute(
            "SELECT timestamp, cardcode, whscode, docnum"
            " FROM recorded_orders WHERE username=%s"
            " ORDER BY timestamp DESC LIMIT 50", (session['username'],)
        )
        rows = cur.fetchall()
    cur.close(); conn.close()
    return render_template('history.html', rows=rows)

# Logout de usuarios
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login'))

# Migración de contraseñas de texto plano a Argon2id
def migrate_passwords():
    conn = get_db_connection(); cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT username, password FROM users WHERE active=TRUE")
    users = cur.fetchall()
    for u in users:
        new_h = ph.hash(u['password'])
        cur.execute(
            "UPDATE users SET password=%s WHERE username=%s",
            (new_h, u['username'])
        )
    conn.commit(); cur.close(); conn.close()
    print(f"Migrados {len(users)} usuarios.")

# Entrada principal
if __name__ == "__main__":
    if os.getenv('MIGRATE') == '1':
        migrate_passwords()
    else:
        app.run(
            debug=False,
            host='0.0.0.0',
            port=int(os.getenv('PORT', 5000)),
            ssl_context='adhoc'
        )
