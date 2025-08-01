import os
from functools import wraps
from datetime import timedelta

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
from requests.exceptions import SSLError, RequestException

# Se define ruta base para archivos de certificado
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Decorador para controlar acceso por roles
def roles_required(*permitted_roles):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Verificación si el rol en sesión está permitido
            if session.get("role") not in permitted_roles:
                # Se devuelve 403 Forbidden en caso de no tener permiso
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
# Se define duración de sesión permanente
tmp = timedelta(minutes=30)
app.permanent_session_lifetime = tmp

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

# Se define SECRET_KEY para sesiones
app.secret_key = os.getenv("SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("SECRET_KEY no está configurada en las Environment Variables")

# Se configuran parámetros del Service Layer de SAP
SERVICE_LAYER_URL = os.getenv(
    "SERVICE_LAYER_URL",
    "https://hwvdvsbo04.virtualdv.cloud:50000/b1s/v1"
)
COMPANY_DB  = os.getenv("COMPANY_DB", "PRDBERSA")
SL_USER     = os.getenv("SL_USER", "brsuser02")
SL_PASSWORD = os.getenv("SL_PASSWORD", "$PniBvQ7rBa6!A")

# Se define conexión a la base de datos PostgreSQL (Neon)
def get_db_connection():
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        raise RuntimeError("DATABASE_URL no está configurada en las Environment Variables")
    return psycopg2.connect(db_url, sslmode='require', cursor_factory=RealDictCursor)

# Ruta raíz redirige a login
@app.route("/")
def index():
    return redirect(url_for("login"))

# Ruta de login
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        user = request.form.get("username")
        pwd  = request.form.get("password")
        conn = get_db_connection()
        cur  = conn.cursor()
        # Se consulta usuario activo con hash
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
                # Verificación y rehash si cambian parámetros
                if ph.check_needs_rehash(row['hashed']):
                    new_hash = ph.hash(pwd)
                    cur.execute(
                        "UPDATE users SET password=%s WHERE username=%s",
                        (new_hash, user)
                    )
                    conn.commit()
                # Se inicia sesión
                session.permanent    = True
                session["username"] = row['username']
                session["role"]     = row['role']
                # Se cargan almacenes asociados
                cur.execute(
                    "SELECT whscode FROM user_warehouses WHERE username=%s",
                    (user,)
                )
                whs = cur.fetchall()
                # Se define lista de códigos
                session["warehouses"] = [w['whscode'] for w in whs]
                cur.close(); conn.close()
                return redirect(url_for("dashboard"))
        else:
            error = "Credenciales inválidas."
        cur.close(); conn.close()
    return render_template("login.html", error=error)

# Ruta de dashboard
@app.route("/dashboard")
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    cur  = conn.cursor()
    # Se obtienen ítems
    cur.execute("SELECT itemcode, description FROM items_map")
    items = cur.fetchall()
    cur.close(); conn.close()
    return render_template(
        "dashboard.html", username=session['username'], items=items
    )

# Envío de órdenes a SAP
@app.route("/submit", methods=["POST"])
def submit():
    if 'username' not in session:
        return redirect(url_for('login'))
    date = request.form.get('date')
    if not date:
        flash('Por favor selecciona una fecha para la orden.', 'error')
        return redirect(url_for('dashboard'))
    # Construcción de líneas de orden
    lines = []
    for code, qty in zip(
        request.form.getlist('item_code'),
        request.form.getlist('quantity')
    ):
        try:
            q = int(qty)
        except ValueError:
            q = 0
        if q > 0:
            lines.append({
                'ItemCode':      code,
                'Quantity':      q,
                'WarehouseCode': session['warehouses'][0]
            })
    order = {
        'CardCode':      session.get('cardcode'),
        'DocDate':       date,
        'DocDueDate':    date,
        'DocumentLines': lines
    }
    try:
        # Autenticación Service Layer
        auth_payload = {
            'CompanyDB': COMPANY_DB,
            'UserName':  SL_USER,
            'Password':  SL_PASSWORD
        }
        auth = requests.post(
            f"{SERVICE_LAYER_URL}/Login",
            json=auth_payload,
            verify=os.path.join(BASE_DIR, 'certs', 'sl-cert-fullchain.crt')
        )
        auth.raise_for_status()
        session_id = auth.json().get('SessionId')
        cookies    = {'B1SESSION': session_id}
        headers    = {'Prefer': 'return=representation'}
        resp = requests.post(
            f"{SERVICE_LAYER_URL}/Orders",
            json=order,
            cookies=cookies,
            headers=headers,
            verify=os.path.join(BASE_DIR, 'certs', 'sl-cert-fullchain.crt')
        )
        resp.raise_for_status()
    except SSLError:
        flash('No se pudo verificar el certificado SSL con SAP.', 'error')
        return redirect(url_for('dashboard'))
    except RequestException as e:
        flash(f'Error conectando con SAP: {e}', 'error')
        return redirect(url_for('dashboard'))
    # Guardado en historial
    data     = resp.json()
    docnum   = data.get('DocNum')
    docentry = data.get('DocEntry')
    conn = get_db_connection()
    cur  = conn.cursor()
    cur.execute(
        """
        INSERT INTO recorded_orders (timestamp, username, whscode, cardcode, docentry, docnum)
        VALUES (NOW(), %s, %s, %s, %s, %s)
        """,
        (
            session['username'],
            session['warehouses'][0],
            session.get('cardcode'),
            docentry, docnum
        )
    )
    conn.commit(); cur.close(); conn.close()
    return render_template('result.html', success=True, docnum=docnum, docentry=docentry)

# Historial de órdenes
@app.route("/history")
def history():
    if 'username' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    cur  = conn.cursor()
    # Si es manager, se filtra por varios almacenes
    if session.get('role') == 'manager':
        whs = session.get('warehouses', [])
        if whs:
            cur.execute(
                "SELECT timestamp, cardcode, whscode, docnum"
                " FROM recorded_orders WHERE whscode = ANY(%s)"
                " ORDER BY timestamp DESC LIMIT 50", (whs,)
            )
        else:
            rows = []
    else:
        # Usuarios normales ven solo su propio historial
        cur.execute(
            "SELECT timestamp, cardcode, whscode, docnum"
            " FROM recorded_orders WHERE username=%s"
            " ORDER BY timestamp DESC LIMIT 50", (session['username'],)
        )
    if cur.statusmessage.startswith('SELECT'):
        rows = cur.fetchall()
    cur.close(); conn.close()
    return render_template('history.html', rows=rows)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login'))

# Migración de contraseñas de texto plano a Argon2id
def migrate_passwords():
    conn = get_db_connection()
    cur  = conn.cursor(cursor_factory=RealDictCursor)
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
