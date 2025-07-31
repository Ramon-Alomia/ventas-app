import os
import requests
import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Flask, render_template, request, redirect, session, url_for, flash
from datetime import timedelta
from flask_talisman import Talisman
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError

# ─── Configuración Argon2id ─────────────────────────────────────────────────
ph = PasswordHasher(
    time_cost=2,        # iteraciones
    memory_cost=102400, # memoria en KiB (100 MiB)
    parallelism=8,      # hilos
    hash_len=32,        # longitud del hash
    salt_len=16,        # longitud de la salt
    type=Type.ID
)

# ─── Configuración de Flask ──────────────────────────────────────────────────
app = Flask(__name__)

# ─── Configuración de seguridad de sesión ─────────────────────────────────────
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)
app.permanent_session_lifetime = timedelta(minutes=30)

# ─── Content Security Policy (CSP) ─────────────────────────────────────────────
csp = {
    'default-src': ["'self'"],
    'script-src':  ["'self'", 'cdnjs.cloudflare.com'],
    'style-src':   ["'self'", 'cdnjs.cloudflare.com'],
    'img-src':     ["'self'", 'data:']
}

# ─── Inicializar Talisman con CSP y HSTS ───────────────────────────────────────
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

# ─── SECRET_KEY para sesiones ─────────────────────────────────────────────────
app.secret_key = os.getenv("SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("SECRET_KEY no está configurada en las Environment Variables")

# ─── Configuración de Service Layer de SAP ────────────────────────────────────
SERVICE_LAYER_URL = os.getenv(
    "SERVICE_LAYER_URL",
    "https://hwvdvsbo04.virtualdv.cloud:50000/b1s/v1"
)
COMPANY_DB  = os.getenv("COMPANY_DB", "PRDBERSA")
SL_USER     = os.getenv("SL_USER", "brsuser02")
SL_PASSWORD = os.getenv("SL_PASSWORD", "$PniBvQ7rBa6!A")

# ─── Conexión a PostgreSQL (Neon) ──────────────────────────────────────────────
def get_db_connection():
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        raise RuntimeError("DATABASE_URL no está configurada en las Environment Variables")
    return psycopg2.connect(db_url, sslmode='require', cursor_factory=RealDictCursor)

# ─── Rutas de la aplicación ───────────────────────────────────────────────────
@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        user = request.form.get("username")
        pwd  = request.form.get("password")

        conn = get_db_connection()
        cur  = conn.cursor()
        cur.execute(
            """
            SELECT username, password AS hashed, whscode
              FROM users
             WHERE username = %s
               AND active = TRUE
            """, (user,)
        )
        row = cur.fetchone()
        cur.close()
        conn.close()

        if row:
            try:
                ph.verify(row['hashed'], pwd)
            except VerifyMismatchError:
                error = "Credenciales inválidas."
            else:
                session.permanent = True
                session['username'] = row['username']
                session['whscode']  = row['whscode']

                # Re-hashea si es necesario
                if ph.check_needs_rehash(row['hashed']):
                    new_hash = ph.hash(pwd)
                    conn2 = get_db_connection()
                    cur2  = conn2.cursor()
                    cur2.execute(
                        "UPDATE users SET password = %s WHERE username = %s",
                        (new_hash, user)
                    )
                    conn2.commit()
                    cur2.close()
                    conn2.close()

                return redirect(url_for('dashboard'))
        else:
            error = "Credenciales inválidas."

    return render_template("login.html", error=error)

@app.route("/dashboard")
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cur  = conn.cursor()
    cur.execute("SELECT itemcode, description FROM items_map")
    items = cur.fetchall()
    cur.close()
    conn.close()

    return render_template("dashboard.html", username=session['username'], items=items)

@app.route("/submit", methods=["POST"])
def submit():
    if 'username' not in session:
        return redirect(url_for('login'))

    date = request.form.get('date')
    if not date:
        flash('Por favor selecciona una fecha para la orden.', 'error')
        return redirect(url_for('dashboard'))

    codes = request.form.getlist('item_code')
    qtys  = request.form.getlist('quantity')
    lines = []
    for code, q in zip(codes, qtys):
        try:
            qty = int(q)
        except ValueError:
            qty = 0
        if qty > 0:
            lines.append({
                'ItemCode':      code,
                'Quantity':      qty,
                'WarehouseCode': session['whscode']
            })

    order = {
        'CardCode':      session.get('cardcode'),
        'DocDate':       date,
        'DocDueDate':    date,
        'DocumentLines': lines
    }

    # Autenticación Service Layer
    auth_payload = {
        'CompanyDB': COMPANY_DB,
        'UserName':  SL_USER,
        'Password':  SL_PASSWORD
    }
    auth_resp = requests.post(
        f"{SERVICE_LAYER_URL}/Login",
        json=auth_payload,
        verify='certs/sl-cert.crt'
    )
    if auth_resp.status_code != 200:
        flash('Error al autenticar en Service Layer', 'error')
        return redirect(url_for('dashboard'))

    session_id = auth_resp.json().get('SessionId')
    cookies    = {'B1SESSION': session_id}
    headers    = {'Prefer': 'return=representation'}

    resp = requests.post(
        f"{SERVICE_LAYER_URL}/Orders",
        json=order,
        cookies=cookies,
        headers=headers,
        verify='certs/sl-cert.crt'
    )

    if resp.status_code in (200,201):
        data     = resp.json()
        docnum   = data.get('DocNum')
        docentry = data.get('DocEntry')

        conn = get_db_connection()
        cur  = conn.cursor()
        cur.execute(
            """
            INSERT INTO recorded_orders
              (timestamp, username, whscode, cardcode, docentry, docnum)
            VALUES (NOW(), %s, %s, %s, %s, %s)
            """,
            (
                session['username'],
                session['whscode'],
                session.get('cardcode'),
                docentry,
                docnum
            )
        )
        conn.commit()
        cur.close()
        conn.close()

        return render_template('result.html', success=True, docnum=docnum, docentry=docentry)
    else:
        return render_template('result.html', success=False, error=resp.text)

@app.route("/history")
def history():
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cur  = conn.cursor()
    cur.execute(
        """
        SELECT timestamp, cardcode, whscode, docnum
          FROM recorded_orders
         WHERE username = %s
         ORDER BY timestamp DESC
         LIMIT 50
        """,
        (session['username'],)
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()

    return render_template('history.html', rows=rows)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login'))


def migrate_passwords():
    """
    Migra contraseñas en texto plano a hashes Argon2id. Ejecutar solo una vez.
    """
    conn = get_db_connection()
    cur  = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT username, password FROM users WHERE active = TRUE")
    users = cur.fetchall()
    for u in users:
        plain = u['password']
        hashed = ph.hash(plain)
        cur.execute(
            "UPDATE users SET password = %s WHERE username = %s",
            (hashed, u['username'])
        )
    conn.commit(); cur.close(); conn.close()
    print(f"Migrados {len(users)} usuarios.")

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
