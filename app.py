'''
app.py - Aplicación Flask para capturar ventas diarias y subirlas a SAP B1 via Service Layer
Estructura de proyecto:

/tu-proyecto
  ├── app.py
  ├── database.db
  └── templates/
        ├── login.html
        ├── dashboard.html
        └── result.html
'''

# Si no funciona 'import requests', usar pip._vendor.requests como alternativa:
# import pip._vendor.requests as requests

import sqlite3
from flask import Flask, render_template, request, redirect, session, url_for, flash
import sys
#try:
import requests # type: ignore
#except ImportError:
#    import pip._vendor.requests as requests

app = Flask(__name__)
app.secret_key = 'TU_SECRET_KEY_AQUI'  # Cambia por una cadena segura
DATABASE = 'database.db'
SERVICE_LAYER_URL = 'https://hwvdvsbo04.virtualdv.cloud:50000/b1s/v1'

# Función auxiliar para conectar a la base SQLite
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Permite acceder a columnas por nombre
    return conn

# Ruta raíz que redirige a login
@app.route('/')
def index():
    return redirect(url_for('login'))

# Ruta de Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    print("Entrando a /login, método:", request.method, file=sys.stderr)
    error = None
    if request.method == 'POST':
        user = request.form['username']
        pwd  = request.form['password']
        conn = get_db_connection()
        cur  = conn.execute(
            'SELECT * FROM users WHERE username = ? AND password = ? AND active = 1',
            (user, pwd)
        )
        row = cur.fetchone()
        conn.close()

        if row:
            session['username'] = row['username']
            session['whscode']  = row['whscode']
            # Obtener CardCode del almacén
            conn = get_db_connection()
            cur  = conn.execute(
                'SELECT cardcode FROM warehouses WHERE whscode = ?',
                (row['whscode'],)
            )
            w = cur.fetchone()
            conn.close()
            session['cardcode'] = w['cardcode']
            return redirect(url_for('dashboard'))
        else:
            error = 'Credenciales inválidas.'
    return render_template('login.html', error=error)

# Ruta de Dashboard (solo accesible si está logueado)
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    # ① Carga los ítems permitidos
    conn   = get_db_connection()
    items  = conn.execute('SELECT itemcode, description FROM items_map').fetchall()
    conn.close()

  # ② Pásalos al template junto con el usuario
    return render_template('dashboard.html',
                           username=session['username'],
                           items=items)

# Ruta para procesar el formulario y enviar la orden a SAP B1
@app.route('/submit', methods=['POST'])
def submit():
    if 'username' not in session:
        return redirect(url_for('login'))

    # ① Leer la fecha
    date = request.form.get('date')
    if not date:
        flash('Por favor selecciona una fecha para la orden.', 'error')
        return redirect(url_for('dashboard'))

    # ② Leer líneas
    items = request.form.getlist('item_code')
    qtys  = request.form.getlist('quantity')
    # (aquí puedes validar también items & qtys)

    # ③ Construir líneas
    lines = []
    for code, q in zip(items, qtys):
        if q and int(q) > 0:
            lines.append({
                'ItemCode':      code,
                'Quantity':      int(q),
                'WarehouseCode': session['whscode']
            })

    # ④ Aquí asegúrate de pasar DocDate y DocDueDate
    order = {
        'CardCode':      session['cardcode'],
        'DocDate':       date,
        'DocDueDate':    date,
        'DocumentLines': lines
    }


    # Autenticación al Service Layer
    auth_payload = {
        'CompanyDB': 'PRDBERSA',
        'UserName': 'brsuser02',
        'Password': '$PniBvQ7rBa6!A'
    }
    auth_resp = requests.post(
        f'{SERVICE_LAYER_URL}/Login',
        json=auth_payload,
        verify=False
    )
    if auth_resp.status_code != 200:
        flash('Error al autenticar en Service Layer')
        return redirect(url_for('dashboard'))

    session_id = auth_resp.json().get('SessionId')
    cookies    = {'B1SESSION': session_id}

    # Enviar la orden de venta y pedir todo el contenido de la respuesta
    headers = {
        'Prefer': 'return=representation'
    }
    resp = requests.post(
        f'{SERVICE_LAYER_URL}/Orders',
        json=order,
        cookies=cookies,
        headers=headers,
        verify=False
    )

    if resp.status_code in (200, 201):
        data   = resp.json()
        docnum = data.get('DocNum')      # Número de documento visible en SAP
        docent = data.get('DocEntry')    # ID interno
        
        # --- Nuevo bloque: grabar en histórico ---
        conn = get_db_connection()
        conn.execute('''
          INSERT INTO recorded_orders
            (timestamp, username, whscode, cardcode, docentry, docnum)
          VALUES
            (datetime('now','localtime'),?,?,?,?,?)
        ''', (session['username'],
              session['whscode'],
              session['cardcode'],
              docent,
              docnum))
        conn.commit()
        conn.close()
        
        return render_template('result.html',
                               success=True,
                               docnum=docnum,
                               docentry=docent)
    else:
        return render_template('result.html', success=False, error=resp.text)

# Ruta de cierre de sesión
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/history')
def history():
    # Si no hay sesión, redirige al login
    if 'username' not in session:
        return redirect(url_for('login'))

    # Lee las últimas 50 órdenes de tu tabla recorded_orders
    conn = get_db_connection()
    rows = conn.execute('''
      SELECT timestamp, cardcode, whscode, docnum
      FROM recorded_orders
      WHERE username = ?
      ORDER BY id DESC
      LIMIT 50
    ''', (session['username'],)).fetchall()
    conn.close()

    return render_template('history.html', rows=rows)

if __name__ == '__main__':
    app.run(debug=True)
