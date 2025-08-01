
import os
import requests
import psycopg2
from functools import wraps
from flask import Flask, render_template, request, redirect, session, url_for, flash, abort
from psycopg2.extras import RealDictCursor
from datetime import timedelta
from flask_talisman import Talisman
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError, InvalidHashError

# Se define un decorador para controlar acceso por roles
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

# ─── Configuración de Argon2id para hashing de contraseñas ────────────────
ph = PasswordHasher(
    time_cost=2,         # Se define número de iteraciones de CPU
    memory_cost=102400,  # Se define memoria dedicada en KiB (100 MiB)
    parallelism=8,       # Se define grado de paralelismo
    hash_len=32,         # Se define longitud del hash resultante
    salt_len=16,         # Se define longitud de la salt aleatoria
    type=Type.ID         # Se usa el modo Argon2id
)

# ─── Inicialización de la aplicación Flask ───────────────────────────────
app = Flask(__name__)

# ─── Configuración de cookies y sesión segura ──────────────────────────────
app.config.update(
    SESSION_COOKIE_SECURE=True,    # Se envían cookies solo por HTTPS
    SESSION_COOKIE_HTTPONLY=True,  # Se evita acceso a cookies desde JavaScript
    SESSION_COOKIE_SAMESITE='Lax'  # Se aplica protección CSRF básica
)
# Se define tiempo de vida de la sesión permanente
app.permanent_session_lifetime = timedelta(minutes=30)

# ─── Definición de políticas de seguridad de contenido (CSP) ───────────────
csp = {
    'default-src': ["'self'"],
    'script-src':  ["'self'", 'cdnjs.cloudflare.com'],
    'style-src':   ["'self'", 'cdnjs.cloudflare.com'],
    'img-src':     ["'self'", 'data:' ]
}
# Se inicializa Talisman para aplicar CSP y HSTS
Talisman(
    app,
    content_security_policy=csp,
    force_https=True,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000
)

# Se añaden cabeceras de seguridad adicionales
@app.after_request
def apply_secure_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'                       # Se previene clickjacking
    response.headers['X-Content-Type-Options'] = 'nosniff'             # Se impide sniffing de contenido
    response.headers['Referrer-Policy'] = 'no-referrer-when-downgrade'  # Se controla política de referer
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# ─── Clave secreta para firmar sesiones ───────────────────────────────────
app.secret_key = os.getenv("SECRET_KEY")
if not app.secret_key:
    # Se verifica que SECRET_KEY esté definida en el entorno
    raise RuntimeError("SECRET_KEY no está configurada en las Environment Variables")

# ─── Configuración de credenciales para Service Layer de SAP ──────────────
SERVICE_LAYER_URL = os.getenv(
    "SERVICE_LAYER_URL",
    "https://hwvdvsbo04.virtualdv.cloud:50000/b1s/v1"
)
COMPANY_DB  = os.getenv("COMPANY_DB", "PRDBERSA")  # Se define base de datos
SL_USER     = os.getenv("SL_USER", "brsuser02")   # Se define usuario SAP
SL_PASSWORD = os.getenv("SL_PASSWORD", "$PniBvQ7rBa6!A")  # Se define contraseña SAP

# ─── Función para obtener conexión a PostgreSQL (Neon) con SSL ────────────
def get_db_connection():
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        # Se verifica que DATABASE_URL esté definida en el entorno
        raise RuntimeError("DATABASE_URL no está configurada en las Environment Variables")
    # Se retorna conexión con sslmode=require y cursor RealDictCursor
    return psycopg2.connect(db_url, sslmode='require', cursor_factory=RealDictCursor)

# ─── Redirección inicial al login ─────────────────────────────────────────
@app.route("/")
def index():
    # Se redirige a la ruta de login
    return redirect(url_for("login"))

# ─── Ruta de login con lógica de hashing y migración on-the-fly ───────────
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        # Se obtienen credenciales desde el formulario
        user = request.form.get("username")
        pwd  = request.form.get("password")
        conn = get_db_connection()
        cur  = conn.cursor()
        # Se consulta hash y rol del usuario activo
        cur.execute(
            """
            SELECT username, password AS hashed, role
              FROM users
             WHERE username = %s AND active = TRUE
            """,
            (user,)
        )
        row = cur.fetchone()
        if row:
            try:
                # Verificación de hash Argon2 existente
                ph.verify(row["hashed"], pwd)
            except VerifyMismatchError:
                # Se indica error si la contraseña no coincide con el hash
                error = "Credenciales inválidas."
            except InvalidHashError:
                # Se re-hashea en caso de contraseña en claro en DB
                if pwd == row["hashed"]:
                    new_hash = ph.hash(pwd)
                    conn2 = get_db_connection()
                    cur2  = conn2.cursor()
                    # Se actualiza el hash en la base de datos
                    cur2.execute(
                        "UPDATE users SET password = %s WHERE username = %s",
                        (new_hash, user)
                    )
                    conn2.commit()
                    cur2.close()
                    conn2.close()
                else:
                    error = "Credenciales inválidas."
            else:
                # Verificación de necesidad de re-hasheo por nuevos parámetros
                if ph.check_needs_rehash(row["hashed"]):
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
            # Si no hubo error, se inicia sesión y se cargan almacenes
            if not error:
                session.permanent    = True
                session["username"] = row["username"]
                session["role"]     = row["role"]
                cur.execute(
                    "SELECT whscode FROM user_warehouses WHERE username = %s",
                    (user,)
                )
                wh_rows = cur.fetchall()
                # Se almacena lista de almacenes en sesión
                session["warehouses"] = [w[0] for w in wh_rows]
                cur.close()
                conn.close()
                # Se redirige al dashboard
                return redirect(url_for("dashboard"))
        else:
            error = "Credenciales inválidas."
        cur.close()
        conn.close()
    # Se renderiza el formulario de login con el posible mensaje de error
    return render_template("login.html", error=error)

# ─── Vista principal donde se carga catálogo de items ────────────────────
@app.route("/dashboard")
def dashboard():
    if 'username' not in session:
        # Se verifica sesión activa antes de mostrar dashboard
        return redirect(url_for('login'))
    conn = get_db_connection()
    cur  = conn.cursor()
    cur.execute("SELECT itemcode, description FROM items_map")
    items = cur.fetchall()
    cur.close()
    conn.close()
    # Se renderiza dashboard con usuario e ítems
    return render_template("dashboard.html", username=session['username'], items=items)

# ─── Ruta para envío de órdenes y registro en PostgreSQL ────────────────
@app.route("/submit", methods=["POST"])
def submit():
    if 'username' not in session:
        return redirect(url_for('login'))
    date = request.form.get('date')
    if not date:
        flash('Por favor selecciona una fecha para la orden.', 'error')
        return redirect(url_for('dashboard'))
    # Se construyen líneas de orden desde el formulario
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
                'WarehouseCode': session['warehouses'][0]  # Se usa el primer almacén asignado
            })
    order = {
        'CardCode':      session.get('cardcode'),
        'DocDate':       date,
        'DocDueDate':    date,
        'DocumentLines': lines
    }
    # Autenticación en Service Layer de SAP
    auth_resp = requests.post(
        f"{SERVICE_LAYER_URL}/Login",
        json={'CompanyDB': COMPANY_DB, 'UserName': SL_USER, 'Password': SL_PASSWORD},
        verify='certs/sl-cert.crt'
    )
    if auth_resp.status_code != 200:
        flash('Error al autenticar en Service Layer', 'error')
        return redirect(url_for('dashboard'))
    session_id = auth_resp.json().get('SessionId')
    cookies    = {'B1SESSION': session_id}
    headers    = {'Prefer': 'return=representation'}
    # Envío de la orden a SAP
    resp = requests.post(
        f"{SERVICE_LAYER_URL}/Orders",
        json=order,
        cookies=cookies,
        headers=headers,
        verify='certs/sl-cert.crt'
    )
    if resp.status_code in (200, 201):
        data     = resp.json()
        docnum   = data.get('DocNum')
        docentry = data.get('DocEntry')
        conn = get_db_connection()
        cur  = conn.cursor()
        # Se registra orden en tabla recorded_orders
        cur.execute(
            """
            INSERT INTO recorded_orders (timestamp, username, whscode, cardcode, docentry, docnum)
            VALUES (NOW(), %s, %s, %s, %s, %s)
            """,
            (session['username'], session['warehouses'][0], session.get('cardcode'), docentry, docnum)
        )
        conn.commit()
        cur.close()
        conn.close()
        # Se renderiza página de resultado exitoso
        return render_template('result.html', success=True, docnum=docnum, docentry=docentry)
    # Se renderiza página de error si falla el envío
    return render_template('result.html', success=False, error=resp.text)

# ─── Histórico: filtro según rol y almacenes asignados ──────────────────────
@app.route("/history")
def history():
    if "username" not in session:
        return redirect(url_for("login"))
    conn = get_db_connection()
    cur  = conn.cursor()
    # Se filtra por almacenes si el rol es manager
    if session.get("role") == "manager":
        warehouses = session.get("warehouses", [])
        if warehouses:
            cur.execute(
                """
                SELECT timestamp, cardcode, whscode, docnum
                  FROM recorded_orders
                 WHERE whscode = ANY(%s)
                 ORDER BY timestamp DESC
                 LIMIT 50
                """,
                (warehouses,)
            )
        else:
            rows = []
    else:
        # Se filtra por usuario si no es manager
        cur.execute(
            """
            SELECT timestamp, cardcode, whscode, docnum
              FROM recorded_orders
             WHERE username = %s
             ORDER BY timestamp DESC
             LIMIT 50
            """,
            (session["username"],)
        )
    # Se obtienen filas si hubo SELECT
    if cur.statusmessage.startswith("SELECT"):
        rows = cur.fetchall()
    cur.close()
    conn.close()
    # Se renderiza la vista de histórico con las filas filtradas
    return render_template("history.html", rows=rows)

# ─── Cierre de sesión y limpieza de datos ──────────────────────────────────
@app.route("/logout")
def logout():
    # Se limpia la sesión por completo
    session.clear()
    return redirect(url_for('login'))

# ─── Migración masiva de contraseñas de texto plano a Argon2id ─────────────
def migrate_passwords():
    conn = get_db_connection()
    cur  = conn.cursor(cursor_factory=RealDictCursor)
    # Se obtienen todos los usuarios activos con contraseña en claro
    cur.execute("SELECT username, password FROM users WHERE active = TRUE")
    users = cur.fetchall()
    count = 0
    for u in users:
        # Se genera nuevo hash y se actualiza el registro
        new_hash = ph.hash(u['password'])
        cur.execute(
            "UPDATE users SET password = %s WHERE username = %s",
            (new_hash, u['username'])
        )
        count += 1
    conn.commit()
    cur.close()
    conn.close()
    # Se imprime cantidad de usuarios migrados
    print(f"Migrados {count} usuarios.")

# ─── Entrada principal: decidir migrar o arrancar servidor Flask ───────────
if __name__ == "__main__":
    if os.getenv('MIGRATE') == '1':
        # Se ejecuta migración de contraseñas y se termina el proceso
        migrate_passwords()
    else:
        # Se inicia servidor Flask con HTTPS adhoc para desarrollo
        app.run(
            debug=False,
            host='0.0.0.0',
            port=int(os.getenv('PORT', 5000)),
            ssl_context='adhoc'
        )
