import os
import sys
import requests
import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Flask, render_template, request, redirect, session, url_for, flash

app = Flask(__name__)
# Clave secreta para sesiones — configúrala como variable de entorno en Render
app.secret_key = os.getenv("SECRET_KEY", ";$b0$40~0J=::Xm!0g|")

# URL del Service Layer de SAP — opcionalmente ponla también como env var
SERVICE_LAYER_URL = os.getenv(
    "SERVICE_LAYER_URL",
    "https://hwvdvsbo04.virtualdv.cloud:50000/b1s/v1"
)
COMPANY_DB    = os.getenv("COMPANY_DB", "PRDBERSA")
SL_USER       = os.getenv("SL_USER", "brsuser02")
SL_PASSWORD   = os.getenv("SL_PASSWORD", "$PniBvQ7rBa6!A")


def get_db_connection():
    """Abre una conexión a PostgreSQL usando la URL en la variable DATABASE_URL."""
    db_url = os.getenv("DATABASE_URL")
    conn = psycopg2.connect(db_url, cursor_factory=RealDictCursor)
    return conn


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
            # Guardar sesión
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

    # Leer líneas de la orden
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
        data    = resp.json()
        docnum  = data.get("DocNum")
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


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
