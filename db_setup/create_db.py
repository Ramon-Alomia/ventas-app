import sqlite3

# 1. Conectar (o crear) la base de datos
conn = sqlite3.connect('database.db')
cursor = conn.cursor()

# 2. Crear tabla de almacenes
cursor.execute('''
CREATE TABLE IF NOT EXISTS warehouses (
    whscode TEXT PRIMARY KEY,
    cardcode TEXT NOT NULL,
    name TEXT NOT NULL
)
''')

# 3. Crear tabla de usuarios
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT NOT NULL,
    whscode TEXT NOT NULL,
    active INTEGER NOT NULL,
    FOREIGN KEY (whscode) REFERENCES warehouses(whscode)
)
''')

# 4. Crear tabla de Items
cursor.execute('''
CREATE TABLE IF NOT EXISTS items_map (
  itemcode TEXT PRIMARY KEY,
  description TEXT NOT NULL
)
''')

# 4. Poblar las tablas con tus datos
warehouses = [
    ('IMSSVE16', 'B0008', 'Imssve Tlapacoyan'),
    ('IMSSVE17', 'B0008', 'Immsve Tempoal'),
    ('IMSSVE18', 'B0008', 'Imssve Regional Poza Rica')
]

users = [
    ('User0001', '1TjHi6#y~4£4', 'IMSSVE16', 1),
    ('User0002', '5}2%awAvT*,6',   'IMSSVE17', 1),
    ('User0003', '40V1aTn@H@wq',  'IMSSVE18', 1)
]

items = [
  ('11713', 'Blanda: Cena'),
  ('11714', 'Blanda Mecánica: Desayuno'),
  ('11715', 'Blanda Mecánica: Comida'),
]

cursor.execute('''
CREATE TABLE IF NOT EXISTS recorded_orders (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp   TEXT    NOT NULL,
  username    TEXT    NOT NULL,
  whscode     TEXT    NOT NULL,
  cardcode    TEXT    NOT NULL,
  docentry    INTEGER NOT NULL,
  docnum      INTEGER NOT NULL
)
''')

cursor.executemany('INSERT OR IGNORE INTO warehouses VALUES (?,?,?)', warehouses)
cursor.executemany('INSERT OR IGNORE INTO users VALUES (?,?,?,?)', users)
cursor.executemany('INSERT OR IGNORE INTO items_map VALUES (?,?)', items)

# 5. Guardar cambios y cerrar
conn.commit()
conn.close()

print('✅ Base de datos creada y tablas pobladas con éxito.')
