import sqlite3
from werkzeug.security import generate_password_hash

con = sqlite3.connect('database.db')

con.execute("DELETE FROM users")

# Agrega admin con rol 'admin'
con.execute("INSERT INTO users (username, password, rol) VALUES (?, ?, ?)", ("admin", generate_password_hash("200701"), "admin"))
# Agrega usuario normal
con.execute("INSERT INTO users (username, password, rol) VALUES (?, ?, ?)", ("EETP477", generate_password_hash("EETP477"), "usuario"))

con.commit()
con.close()
print("Usuarios creados: admin/200701 (admin) y EETP477/EETP477 (usuario)")