import os
import sys
import requests
import psycopg2
from flask_talisman import Talisman
from psycopg2.extras import RealDictCursor
from flask import Flask, render_template, request, redirect, session, url_for, flash

# ─── Configuración de Flask ────────────────────────────────────────────────────
app = Flask(__name__)

# ─── Configuración de seguridad de sesión ───────────────────────────────────────
app.config.update(
    SESSION_COOKIE_SECURE=True,      # Solo envía cookie por HTTPS
    SESSION_COOKIE_HTTPONLY=True,    # JavaScript no puede leer la cookie
    SESSION_COOKIE_SAMESITE='Lax'    # Protege contra CSRF en algunos casos
)

# ─── Content Security Policy (CSP) ──────────────────────────────────────────────
csp = {
    'default-src': ["'self'"],
    'script-src':  ["'self'", 'cdnjs.cloudflare.com'],
    'style-src':   ["'self'", 'cdnjs.cloudflare.com'],
    'img-src':     ["'self'", 'data:']
    # agrega aquí más directivas si usas otras fuentes, APIs, etc.
}

# ─── Inicializar Talisman con CSP y HSTS ────────────────────────────────────────
Talisman(
    app,
    content_security_policy=csp,
    force_https=True,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000
)

# SECRET_KEY para sesiones: debe definirse en Render como ENV var
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

# ─── Función de conexión a PostgreSQL (Neon) ──────────────────────────────────
def get_db_connection():
    """
    Abre una conexión a PostgreSQL usando la URL en la variable DATABASE_URL.
    Neon requiere SSL; la URI debe terminar en ?sslmode=require
    """
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        raise RuntimeError("DATABASE_URL no está configurada en las Environment Variables")
    # psycopg2 acepta la URI completa con sslmode
    conn = psycopg2.connect(db_url, cursor_factory=RealDictCursor)
    return conn

# ─── Rutas de la aplicación ────────────────────────────────────────────────────
@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    print("Entrando a /login, método:", request.method, file=sys.stderr)
    error = None
    if request.method == "POST":
        user = request.form["username"]
        pwd  = request.form["password"]

        conn = get_db_connection()
        cur  = conn.cursor()
        cur.execute(
            """
            SELECT username, password, whscode
              FROM users
             WHERE username = %s
               AND password = %s
               AND active = TRUE
            """,
            (user, pwd)
        )
        row = cur.fetchone()
        cur.close()
        conn.close()

        if row:
            session["username"] = row["username"]
            session["whscode"]  = row["whscode"]

            # Obtener el CardCode del almacén
            conn = get_db_connection()
            cur  = conn.cursor()
            cur.execute(
                "SELECT cardcode FROM warehouses WHERE whscode = %s",
                (row["whscode"],)
            )
            w = cur.fetchone()
            cur.close()
            conn.close()

            session["cardcode"] = w["cardcode"] if w else None
            return redirect(url_for("dashboard"))
        else:
            error = "Credenciales inválidas."
    return render_template("login.html", error=error)

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    cur  = conn.cursor()
    cur.execute("SELECT itemcode, description FROM items_map")
    items = cur.fetchall()
    cur.close()
    conn.close()

    return render_template(
        "dashboard.html",
        username=session["username"],
        items=items
    )

@app.route("/submit", methods=["POST"])
def submit():
    if "username" not in session:
        return redirect(url_for("login"))

    date = request.form.get("date")
    if not date:
        flash("Por favor selecciona una fecha para la orden.", "error")
        return redirect(url_for("dashboard"))

    # Lee y filtra las líneas de la orden
    items = request.form.getlist("item_code")
    qtys  = request.form.getlist("quantity")
    lines = []
    for code, q in zip(items, qtys):
        try:
            qty = int(q)
        except ValueError:
            qty = 0
        if qty > 0:
            lines.append({
                "ItemCode":      code,
                "Quantity":      qty,
                "WarehouseCode": session["whscode"]
            })

    order = {
        "CardCode":      session["cardcode"],
        "DocDate":       date,
        "DocDueDate":    date,
        "DocumentLines": lines
    }

    # Autenticación en Service Layer
    auth_payload = {
        "CompanyDB": COMPANY_DB,
        "UserName":  SL_USER,
        "Password":  SL_PASSWORD
    }
    auth_resp = requests.post(
        f"{SERVICE_LAYER_URL}/Login",
        json=auth_payload,
        verify=False
    )
    if auth_resp.status_code != 200:
        flash("Error al autenticar en Service Layer", "error")
        return redirect(url_for("dashboard"))

    session_id = auth_resp.json().get("SessionId")
    cookies    = {"B1SESSION": session_id}
    headers    = {"Prefer": "return=representation"}

    # Envío de la orden
    resp = requests.post(
        f"{SERVICE_LAYER_URL}/Orders",
        json=order,
        cookies=cookies,
        headers=headers,
        verify=False
    )

    if resp.status_code in (200, 201):
        data     = resp.json()
        docnum   = data.get("DocNum")
        docentry = data.get("DocEntry")

        # Guardar en histórico en PostgreSQL
        conn = get_db_connection()
        cur  = conn.cursor()
        cur.execute(
            """
            INSERT INTO recorded_orders
              (timestamp, username, whscode, cardcode, docentry, docnum)
            VALUES
              (NOW(), %s, %s, %s, %s, %s)
            """,
            (
                session["username"],
                session["whscode"],
                session["cardcode"],
                docentry,
                docnum
            )
        )
        conn.commit()
        cur.close()
        conn.close()

        return render_template(
            "result.html",
            success=True,
            docnum=docnum,
            docentry=docentry
        )
    else:
        return render_template("result.html", success=False, error=resp.text)

@app.route("/history")
def history():
    if "username" not in session:
        return redirect(url_for("login"))

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
        (session["username"],)
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()

    return render_template("history.html", rows=rows)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ─── Entrada principal ────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Esto genera un certificado temporario auto‑firmado para HTTPS
    app.run(
      debug=False,
      host="0.0.0.0",
      port=5000,
      ssl_context="adhoc"
    )

