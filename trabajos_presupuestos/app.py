import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, make_response
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import pdfkit
from flask_wtf import CSRFProtect

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_SECRET_KEY'] = 'otrosecretomaslargo'
csrf = CSRFProtect(app)
DB = "database.db"

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# --- Autenticación básica ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(UserMixin):
    def __init__(self, id, username, rol):
        self.id = id
        self.username = username
        self.rol = rol

@login_manager.user_loader
def load_user(user_id):
    con = conectar_db()
    user = con.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    con.close()
    if user:
        return User(user[0], user[1], user[3])
    return None

def conectar_db():
    return sqlite3.connect(DB)

def inicializar_db():
    con = conectar_db()
    cur = con.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        rol TEXT DEFAULT 'usuario'
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS trabajos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cliente TEXT NOT NULL,
        descripcion TEXT,
        fecha_inicio TEXT,
        fecha_fin TEXT,
        estado TEXT
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS presupuestos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        trabajo_id INTEGER,
        item TEXT,
        cantidad INTEGER,
        precio_unitario REAL,
        FOREIGN KEY(trabajo_id) REFERENCES trabajos(id)
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS historial (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        trabajo_id INTEGER,
        usuario TEXT,
        accion TEXT,
        fecha TEXT
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS comentarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        trabajo_id INTEGER,
        usuario TEXT,
        comentario TEXT,
        fecha TEXT
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS archivos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        trabajo_id INTEGER,
        nombre TEXT,
        ruta TEXT,
        fecha TEXT
    )''')
    con.commit()
    con.close()

def registrar_historial(trabajo_id, usuario, accion):
    con = conectar_db()
    con.execute('INSERT INTO historial (trabajo_id, usuario, accion, fecha) VALUES (?, ?, ?, ?)',
                (trabajo_id, usuario, accion, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    con.commit()
    con.close()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        con = conectar_db()
        user = con.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        con.close()
        if user and check_password_hash(user[2], password):
            login_user(User(user[0], user[1], user[3]))
            flash('¡Bienvenido!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Usuario o contraseña incorrectos', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Sesión cerrada', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    con = conectar_db()
    total_trabajos = con.execute('SELECT COUNT(*) FROM trabajos').fetchone()[0] or 0
    con.close()
    return render_template('dashboard.html', total_trabajos=total_trabajos)

@app.route('/')
@login_required
def index():
    return redirect(url_for('dashboard'))

@app.route('/trabajos')
@login_required
def trabajos():
    con = conectar_db()
    trabajos = con.execute('SELECT * FROM trabajos').fetchall()
    con.close()
    return render_template('trabajos.html', trabajos=trabajos)

@app.route('/trabajos/nuevo', methods=['GET', 'POST'])
@login_required
def nuevo_trabajo():
    if request.method == 'POST':
        cliente = request.form['cliente']
        descripcion = request.form['descripcion']
        fecha_inicio = request.form['fecha_inicio']
        fecha_fin = request.form['fecha_fin']
        estado = request.form['estado']
        con = conectar_db()
        cur = con.cursor()
        cur.execute('INSERT INTO trabajos (cliente, descripcion, fecha_inicio, fecha_fin, estado) VALUES (?, ?, ?, ?, ?)',
                    (cliente, descripcion, fecha_inicio, fecha_fin, estado))
        con.commit()
        nuevo_id = cur.lastrowid
        registrar_historial(nuevo_id, current_user.username, 'Creó el trabajo')
        con.close()
        flash('Trabajo creado correctamente', 'success')
        return redirect(url_for('trabajos'))
    return render_template('nuevo_trabajo.html')

@app.route('/trabajos/<int:id>')
@login_required
def ver_trabajo(id):
    con = conectar_db()
    trabajo = con.execute('SELECT * FROM trabajos WHERE id=?', (id,)).fetchone()
    presupuestos = con.execute('SELECT * FROM presupuestos WHERE trabajo_id=?', (id,)).fetchall()
    total = sum((p[3] or 0) * (p[4] or 0) for p in presupuestos) if presupuestos else 0
    historial = con.execute('SELECT usuario, accion, fecha FROM historial WHERE trabajo_id=? ORDER BY fecha DESC', (id,)).fetchall()
    comentarios = con.execute('SELECT usuario, comentario, fecha FROM comentarios WHERE trabajo_id=? ORDER BY fecha DESC', (id,)).fetchall()
    archivos = con.execute('SELECT nombre, ruta, fecha FROM archivos WHERE trabajo_id=? ORDER BY fecha DESC', (id,)).fetchall()
    con.close()
    return render_template('ver_trabajo.html', trabajo=trabajo, presupuestos=presupuestos, total=total,
                           historial=historial, comentarios=comentarios, archivos=archivos)

@app.route('/trabajos/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def editar_trabajo(id):
    con = conectar_db()
    cur = con.cursor()
    if request.method == 'POST':
        cliente = request.form['cliente']
        descripcion = request.form['descripcion']
        fecha_inicio = request.form['fecha_inicio']
        fecha_fin = request.form['fecha_fin']
        estado = request.form['estado']
        cur.execute('''
            UPDATE trabajos
            SET cliente=?, descripcion=?, fecha_inicio=?, fecha_fin=?, estado=?
            WHERE id=?
        ''', (cliente, descripcion, fecha_inicio, fecha_fin, estado, id))
        con.commit()
        registrar_historial(id, current_user.username, 'Editó el trabajo')
        con.close()
        flash('Trabajo actualizado', 'success')
        return redirect(url_for('trabajos'))
    trabajo = cur.execute('SELECT * FROM trabajos WHERE id=?', (id,)).fetchone()
    con.close()
    return render_template('editar_trabajo.html', trabajo=trabajo)

@app.route('/trabajos/<int:id>/eliminar', methods=['POST'])
@login_required
def eliminar_trabajo(id):
    if not hasattr(current_user, 'rol') or current_user.rol != 'admin':
        flash('Solo el administrador puede eliminar trabajos', 'danger')
        return redirect(url_for('trabajos'))
    con = conectar_db()
    registrar_historial(id, current_user.username, 'Eliminó el trabajo')
    con.execute('DELETE FROM presupuestos WHERE trabajo_id=?', (id,))
    con.execute('DELETE FROM comentarios WHERE trabajo_id=?', (id,))
    con.execute('DELETE FROM archivos WHERE trabajo_id=?', (id,))
    con.execute('DELETE FROM historial WHERE trabajo_id=?', (id,))
    con.execute('DELETE FROM trabajos WHERE id=?', (id,))
    con.commit()
    con.close()
    flash('Trabajo eliminado', 'info')
    return redirect(url_for('trabajos'))

@app.route('/trabajos/<int:id>/presupuesto/nuevo', methods=['POST'])
@login_required
def agregar_presupuesto(id):
    item = request.form['item']
    cantidad = int(request.form['cantidad'])
    precio_unitario = float(request.form['precio_unitario'])
    con = conectar_db()
    con.execute('INSERT INTO presupuestos (trabajo_id, item, cantidad, precio_unitario) VALUES (?, ?, ?, ?)',
                (id, item, cantidad, precio_unitario))
    con.commit()
    con.close()
    flash('Ítem agregado al presupuesto', 'success')
    return redirect(url_for('ver_trabajo', id=id))

@app.route('/presupuestos/<int:id>/eliminar', methods=['POST'])
@login_required
def eliminar_presupuesto(id):
    con = conectar_db()
    presupuesto = con.execute('SELECT trabajo_id FROM presupuestos WHERE id=?', (id,)).fetchone()
    if presupuesto:
        trabajo_id = presupuesto[0]
        con.execute('DELETE FROM presupuestos WHERE id=?', (id,))
        con.commit()
        con.close()
        flash('Ítem eliminado', 'info')
        return redirect(url_for('ver_trabajo', id=trabajo_id))
    con.close()
    return redirect(url_for('trabajos'))

@app.route('/trabajos/buscar')
@login_required
def buscar_trabajos():
    q = request.args.get('q', '')
    con = conectar_db()
    trabajos = con.execute('SELECT * FROM trabajos WHERE cliente LIKE ? OR descripcion LIKE ?', (f'%{q}%', f'%{q}%')).fetchall()
    con.close()
    return render_template('trabajos.html', trabajos=trabajos, q=q)

@app.route('/trabajos/<int:id>/estado', methods=['POST'])
@login_required
def cambiar_estado(id):
    nuevo_estado = request.form['estado']
    con = conectar_db()
    con.execute('UPDATE trabajos SET estado=? WHERE id=?', (nuevo_estado, id))
    con.commit()
    con.close()
    flash('Estado actualizado', 'success')
    return redirect(url_for('trabajos'))

@app.route('/trabajos/<int:id>/comentario', methods=['POST'])
@login_required
def agregar_comentario(id):
    comentario = request.form['comentario']
    con = conectar_db()
    con.execute('INSERT INTO comentarios (trabajo_id, usuario, comentario, fecha) VALUES (?, ?, ?, ?)',
                (id, current_user.username, comentario, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    con.commit()
    con.close()
    flash('Comentario agregado', 'success')
    return redirect(url_for('ver_trabajo', id=id))

@app.route('/trabajos/<int:id>/archivo', methods=['POST'])
@login_required
def subir_archivo(id):
    archivo = request.files['archivo']
    if archivo:
        filename = secure_filename(archivo.filename)
        ruta = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        archivo.save(ruta)
        con = conectar_db()
        con.execute('INSERT INTO archivos (trabajo_id, nombre, ruta, fecha) VALUES (?, ?, ?, ?)',
                    (id, filename, ruta, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        con.commit()
        con.close()
        flash('Archivo subido', 'success')
    return redirect(url_for('ver_trabajo', id=id))

@app.route('/trabajos/<int:id>/pdf')
@login_required
def exportar_pdf(id):
    con = conectar_db()
    trabajo = con.execute('SELECT * FROM trabajos WHERE id=?', (id,)).fetchone()
    presupuestos = con.execute('SELECT * FROM presupuestos WHERE trabajo_id=?', (id,)).fetchall()
    total = sum((p[3] or 0) * (p[4] or 0) for p in presupuestos) if presupuestos else 0
    con.close()
    rendered = render_template('pdf.html', trabajo=trabajo, presupuestos=presupuestos, total=total)
    pdf = pdfkit.from_string(rendered, False)
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=presupuesto_{id}.pdf'
    return response

@app.route('/historial')
@login_required
def historial():
    if not hasattr(current_user, 'rol') or current_user.rol != 'admin':
        flash('Acceso solo para administradores', 'danger')
        return redirect(url_for('dashboard'))
    con = conectar_db()
    historial = con.execute('''
        SELECT h.fecha, h.usuario, h.accion, h.trabajo_id, t.cliente, t.descripcion
        FROM historial h
        JOIN trabajos t ON h.trabajo_id = t.id
        ORDER BY h.fecha DESC
    ''').fetchall()
    con.close()
    return render_template('historial.html', historial=historial)

if __name__ == '__main__':
    inicializar_db()
 app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
