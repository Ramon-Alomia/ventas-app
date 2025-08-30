import os
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta
from requests.exceptions import SSLError, RequestException
import requests
import psycopg2
import csv
import io
from flask import (
    Flask, render_template, request, redirect,
    session, url_for, flash, abort, jsonify, Response
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

# Configuración SQLAlchemy
from models import db
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

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

# Verificar que el usuario siga activo antes de cada solicitud
@app.before_request
def ensure_user_is_active():
    if request.endpoint in ('login', 'static'):
        return
    username = session.get('username')
    if not username:
        return
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT active FROM users WHERE username=%s", (username,))
    row = cur.fetchone()
    cur.close(); conn.close()
    if not row or not row['active']:
        session.clear()
        flash('Tu usuario ha sido desactivado.', 'error')
        return redirect(url_for('login'))

@app.before_request
def refresh_user_warehouses():
    if request.endpoint in ('login', 'static'):
        return
    username = session.get('username')
    if not username:
        return
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute(
        """
        SELECT w.whscode, w.cardcode, w.whsdesc
        FROM user_warehouses uw
        JOIN warehouses w ON w.whscode = uw.whscode
        WHERE uw.username = %s
        ORDER BY w.whscode, w.cardcode
        """,
        (username,)
    )
    rows = cur.fetchall()
    cur.close(); conn.close()
    warehouses = {}
    for r in rows:
        wh = r['whscode'].strip()
        cardcodes = [c.strip() for c in r['cardcode'].split(',')]
        whsdescs = [d.strip() for d in r['whsdesc'].split(',')]
        for cc, desc in zip(cardcodes, whsdescs):
            warehouses.setdefault(wh, []).append({'cardcode': cc, 'whsdesc': desc})
    session['warehouses'] = list(warehouses.keys())
    session['warehouse_cards'] = warehouses

# Rutas de la aplicación
@app.route("/")

def index():
    if "username" in session:
        return redirect(url_for("dashboard"))
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
                session.permanent   = True
                session['username'] = row['username']
                session['role']     = row['role']
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
    return render_template(
        'dashboard.html',
        username=session['username'],
        warehouses=session.get('warehouse_cards', {}),
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
    selected_whs = request.form.get('warehouse', '').strip()
    if not selected_whs:
        flash('Por favor selecciona un almacén.', 'error')
        return redirect(url_for('dashboard'))
    cardcode = request.form.get('cardcode', '').strip()
    allowed_cards = [c['cardcode'] for c in session.get('warehouse_cards', {}).get(selected_whs, [])]
    if cardcode not in allowed_cards:
        flash('Almacén o cliente inválido.', 'error')
        return redirect(url_for('dashboard'))

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
    whscode = request.args.getlist('whscode')
    user_filter = request.args.getlist('username')

    # Algunos navegadores/envíos front-end mandan "None" como texto cuando no se
    # selecciona una fecha. Esto provocaba que la consulta intentara convertir
    # la cadena "None" a DATE generando un error 500. Normalizamos estos valores
    # para tratarlos como si no se hubiese enviado nada.
    if not start_date or str(start_date).lower() == 'none':
        start_date = None
    if not end_date or str(end_date).lower() == 'none':
        end_date = None

    conn = get_db_connection(); cur = conn.cursor()
    allowed = ('manager', 'admin', 'supervisor')
    query = (
        "SELECT timestamp, username, cardcode, whscode, docnum, itemcode, quantity "
        "FROM recorded_orders WHERE 1=1"
    )
    params = []
    if session.get('role') in allowed:
        if user_filter:
            query += " AND username = ANY(%s)"
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
        query += " AND whscode = ANY(%s)"
        params.append(whscode)
    query += " ORDER BY timestamp DESC LIMIT 100"
    cur.execute(query, params)
    rows = [dict(r) for r in cur.fetchall()]
    for r in rows:
        r['timestamp'] = r['timestamp'].strftime('%d/%m/%Y %H:%M:%S')
    cur.execute("SELECT whscode FROM warehouses ORDER BY whscode")
    warehouses = [r['whscode'] for r in cur.fetchall()]
    users_options = []
    if session.get('role') in allowed:
        cur.execute("SELECT username FROM users WHERE active=TRUE ORDER BY username")
        users_options = [r['username'] for r in cur.fetchall()]
    cur.close(); conn.close()
    filters = {'start_date': start_date, 'end_date': end_date, 'whscode': whscode, 'username': user_filter}
    return render_template(
        'history.html',
        rows=rows,
        filters=filters,
        is_admin=session.get('role') in allowed,
        warehouses=warehouses,
        users_options=users_options,
    )


@app.route("/history/export")
def export_history():
    if 'username' not in session:
        return redirect(url_for('login'))
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    whscode = request.args.getlist('whscode')
    user_filter = request.args.getlist('username')
    
    # Normalizar valores "None" enviados como texto desde el front-end
    # para evitar errores de conversión de fecha.
    if not start_date or str(start_date).lower() == 'none':
        start_date = None
    if not end_date or str(end_date).lower() == 'none':
        end_date = None

    conn = get_db_connection(); cur = conn.cursor()
    allowed = ('manager', 'admin', 'supervisor')
    query = (
        "SELECT timestamp, username, cardcode, whscode, docnum, itemcode, quantity "
        "FROM recorded_orders WHERE 1=1"
    )
    params = []
    if session.get('role') in allowed:
        if user_filter:
            query += " AND username = ANY(%s)"
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
        query += " AND whscode = ANY(%s)"
        params.append(whscode)
    query += " ORDER BY timestamp DESC"
    cur.execute(query, params)
    rows = cur.fetchall()
    cur.close(); conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp", "username", "cardcode", "whscode", "docnum", "itemcode", "quantity"])
    for r in rows:
        ts = r['timestamp']
        ts = ts.strftime('%d/%m/%Y %H:%M:%S') if hasattr(ts, 'strftime') else ts
        writer.writerow([ts, r['username'], r['cardcode'], r['whscode'], r['docnum'], r['itemcode'], r['quantity']])

    response = Response(output.getvalue(), mimetype='text/csv')
    response.headers['Content-Disposition'] = 'attachment; filename=history.csv'
    return response

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
        elif form_type == 'add_item':
            itemcode = request.form.get('itemcode')
            description = request.form.get('description')
            whs_codes = [w.strip() for w in request.form.get('whs_codes', '').split(',') if w.strip()]
            cur.execute(
                """
                INSERT INTO items (itemcode, description)
                VALUES (%s, %s)
                ON CONFLICT (itemcode) DO UPDATE
                SET description=EXCLUDED.description
                """,
                (itemcode, description),
            )
            cur.execute("DELETE FROM item_warehouse WHERE itemcode=%s", (itemcode,))
            for wh in whs_codes:
                cur.execute(
                    "INSERT INTO item_warehouse (itemcode, whscode) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                    (itemcode, wh),
                )
            conn.commit()
        elif form_type == 'delete_item':
            itemcode = request.form.get('itemcode')
            cur.execute("DELETE FROM item_warehouse WHERE itemcode=%s", (itemcode,))
            cur.execute("DELETE FROM items WHERE itemcode=%s", (itemcode,))
            conn.commit()
        elif form_type == 'assign_item_wh':
            itemcode = request.form.get('itemcode')
            whscode = request.form.get('whscode')
            if whscode not in session.get('warehouses', []):
                abort(403)
            cur.execute("SELECT 1 FROM warehouses WHERE whscode=%s", (whscode,))
            if not cur.fetchone():
                abort(400)
            cur.execute(
                """
                INSERT INTO item_warehouse (itemcode, whscode)
                VALUES (%s, %s)
                ON CONFLICT (itemcode, whscode) DO NOTHING
                """,
                (itemcode, whscode),
            )
            conn.commit()
        elif form_type == 'delete_item_wh':
            itemcode = request.form.get('itemcode')
            whscode = request.form.get('whscode')
            cur.execute(
                "DELETE FROM item_warehouse WHERE itemcode=%s AND whscode=%s",
                (itemcode, whscode),
            )
            conn.commit()

    cur.execute("SELECT username, role, active FROM users ORDER BY username")
    users = cur.fetchall()
    for u in users:
        cur.execute("SELECT whscode FROM user_warehouses WHERE username=%s", (u['username'],))
        whs = cur.fetchall()
        u['warehouses'] = [w['whscode'] for w in whs]
    cur.execute("SELECT whscode, cardcode, whsdesc FROM warehouses ORDER BY whscode")
    warehouses = cur.fetchall()
    cur.execute(
        """
        SELECT i.itemcode, i.description,
               COALESCE(
                   json_agg(
                       json_build_object('whscode', iw.whscode) ORDER BY iw.whscode
                   ) FILTER (WHERE iw.whscode IS NOT NULL),
                   '[]'
               ) AS warehouses
        FROM items i
        LEFT JOIN item_warehouse iw ON i.itemcode = iw.itemcode
        GROUP BY i.itemcode, i.description
        ORDER BY i.itemcode
        """
    )
    items = cur.fetchall()
    cur.close(); conn.close()
    return render_template('admin.html', users=users, warehouses=warehouses, items=items)

@app.route("/items", methods=["GET"])
def get_items():
    if 'username' not in session:
        return abort(403)
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute(
        """
        SELECT i.itemcode, i.description, iw.whscode
        FROM items i
        JOIN item_warehouse iw USING (itemcode)
        JOIN user_warehouses uw ON uw.whscode = iw.whscode
        WHERE uw.username = %s
        """,
        (session['username'],),
    )
    rows = cur.fetchall()
    cur.close(); conn.close()
    items = {}
    for r in rows:
        itm = items.setdefault(r['itemcode'], {
            'itemcode': r['itemcode'],
            'description': r['description'],
            'warehouses': []
        })
        itm['warehouses'].append({'whscode': r['whscode']})
    return jsonify(list(items.values()))


@app.route("/items/<itemcode>", methods=["GET"])
def get_item(itemcode):
    if 'username' not in session:
        return abort(403)
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute(
        """
        SELECT i.itemcode, i.description, iw.whscode
        FROM items i
        JOIN item_warehouse iw USING (itemcode)
        JOIN user_warehouses uw ON uw.whscode = iw.whscode
        WHERE uw.username = %s AND i.itemcode = %s
        """,
        (session['username'], itemcode),
    )
    rows = cur.fetchall()
    cur.close(); conn.close()
    if not rows:
        return abort(404)
    item = {
        'itemcode': rows[0]['itemcode'],
        'description': rows[0]['description'],
        'warehouses': []
    }
    for r in rows:
        item['warehouses'].append({'whscode': r['whscode']})
    return jsonify(item)


@app.route("/warehouses/<whscode>/items", methods=["GET"])
def items_by_wh(whscode):
    if 'username' not in session:
        return abort(403)
    whscode = whscode.strip()
    if whscode not in session.get('warehouses', []):
        return abort(403)
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute(
        """
        SELECT i.itemcode, i.description
        FROM item_warehouse iw
        JOIN items i ON i.itemcode = iw.itemcode
        WHERE TRIM(iw.whscode) = %s
        """,
        (whscode,),
    )
    rows = cur.fetchall()
    cur.close(); conn.close()
    return jsonify([
        {
            'itemcode': r['itemcode'],
            'description': r['description']
        }
        for r in rows
    ])


@app.route("/items", methods=["POST", "PUT"])
@roles_required('admin')
def upsert_item():
    if 'username' not in session:
        return abort(403)
    data = request.get_json(force=True)
    itemcode = data.get('itemcode')
    description = data.get('description')
    if not itemcode or not description:
        return abort(400)
    warehouses = data.get('warehouses', [])
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO items (itemcode, description)
        VALUES (%s, %s)
        ON CONFLICT (itemcode) DO UPDATE
        SET description = EXCLUDED.description
        """,
        (itemcode, description),
    )
    for w in warehouses:
        whscode = w.get('whscode')
        if whscode is None:
            continue
        if whscode not in session.get('warehouses', []):
            cur.close(); conn.close(); return abort(403)
        cur.execute("SELECT 1 FROM warehouses WHERE whscode=%s", (whscode,))
        if not cur.fetchone():
            cur.close(); conn.close(); return abort(400)
        cur.execute(
            """
            INSERT INTO item_warehouse (itemcode, whscode)
            VALUES (%s, %s)
            ON CONFLICT (itemcode, whscode) DO NOTHING
            """,
            (itemcode, whscode),
        )
    conn.commit(); cur.close(); conn.close()
    return jsonify({'status': 'ok'})


@app.route("/warehouses/<whscode>/items", methods=["POST", "PUT"])
@roles_required('admin')
def upsert_item_wh(whscode):
    if 'username' not in session:
        return abort(403)
    if whscode not in session.get('warehouses', []):
        return abort(403)
    data = request.get_json(force=True)
    itemcode = data.get('itemcode')
    if not itemcode:
        return abort(400)
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT 1 FROM warehouses WHERE whscode=%s", (whscode,))
    if not cur.fetchone():
        cur.close(); conn.close(); return abort(400)
    cur.execute(
        """
        INSERT INTO item_warehouse (itemcode, whscode)
        VALUES (%s, %s)
        ON CONFLICT (itemcode, whscode) DO NOTHING
        """,
        (itemcode, whscode),
    )
    conn.commit(); cur.close(); conn.close()
    return jsonify({'status': 'ok'})

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