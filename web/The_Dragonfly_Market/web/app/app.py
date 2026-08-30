import os, sqlite3, subprocess, json, base64
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, make_response, jsonify
import jwt

APP_DIR = os.path.dirname(__file__)
TEMPLATE_DIR = os.path.join(APP_DIR, '../.templates')
STATIC_DIR = os.path.join(APP_DIR, '../.static')
if not os.path.isdir(TEMPLATE_DIR):
    TEMPLATE_DIR = os.path.join(APP_DIR, '../templates')
if not os.path.isdir(STATIC_DIR):
    STATIC_DIR = os.path.join(APP_DIR, '../static')
app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)
DB = os.getenv('DB_PATH', '/data/dragonfly.db')
SECRET = os.getenv('JWT_SECRET', 'dragonfly-local-secret')

def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    if os.path.exists('/init/init.sql'):
        schema = open('/init/init.sql').read()
    else:
        schema = open(os.path.join(os.path.dirname(__file__), '../../database/init.sql')).read()
    c = db(); c.executescript(schema); c.commit(); c.close()

def token_payload():
    raw = request.cookies.get('dragonfly_session')
    if not raw: return None
    try:
        # Deliberate CTF flaw: accepts unsigned JWTs when alg is none.
        head = json.loads(base64.urlsafe_b64decode(raw.split('.')[0] + '=='))
        if head.get('alg') == 'none':
            return jwt.decode(raw, options={'verify_signature': False})
        return jwt.decode(raw, SECRET, algorithms=['HS256'])
    except Exception:
        return None

@app.context_processor
def inject_session_user():
    return {'session_user': token_payload()}

def auth(required=None):
    def deco(fn):
        @wraps(fn)
        def wrapped(*a, **kw):
            p = token_payload()
            if not p: return redirect(url_for('login'))
            if required and p.get('role') != required: return ('Admin access required', 403)
            return fn(*a, **kw)
        return wrapped
    return deco

@app.get('/health')
def health(): return 'ok'

@app.get('/')
def home(): return render_template('home.html', products=db().execute('SELECT * FROM products LIMIT 3').fetchall())

@app.get('/marketplace')
def marketplace(): return render_template('marketplace.html', products=db().execute('SELECT * FROM products').fetchall())

@app.get('/product/<int:pid>')
def product(pid): return render_template('product.html', product=db().execute('SELECT * FROM products WHERE id=?',(pid,)).fetchone(), requested=False)

@app.route('/login', methods=['GET','POST'])
def login():
    error = None
    if request.method == 'POST':
        u, p = request.form.get('username',''), request.form.get('password','')
        # Deliberate SQLi in the authentication query for stage 1.
        row = db().execute("SELECT id, username, role FROM users WHERE username = '%s' AND password = '%s'" % (u, p)).fetchone()
        if row:
            # Authentication success intentionally always creates a low-privilege session.
            # The admin role is not taken from SQLi-controlled row data.
            token = jwt.encode({'sub': row['username'], 'role': 'user'}, SECRET, algorithm='HS256')
            r = make_response(redirect(url_for('dashboard'))); r.set_cookie('dragonfly_session', token, httponly=True); return r
        error = 'We could not verify those catalogue credentials.'
    return render_template('login.html', error=error)

@app.get('/dashboard')
@auth()
def dashboard(): return render_template('dashboard.html', user=token_payload())

@app.get('/logout')
def logout():
    r = make_response(redirect(url_for('home')))
    r.delete_cookie('dragonfly_session')
    return r

@app.get('/admin')
@auth('admin')
def admin(): return render_template('admin.html', result=None, view=request.args.get('view','connectivity'))

@app.post('/product/<int:pid>/request')
@auth()
def request_notes(pid):
    product = db().execute('SELECT * FROM products WHERE id=?',(pid,)).fetchone()
    return render_template('product.html', product=product, requested=True)

@app.post('/admin/connectivity')
@auth('admin')
def connectivity():
    target = request.form.get('supplier','')
    # Deliberate command injection: the normal operational helper is assembled unsafely.
    result = subprocess.run('getent hosts ' + target + ' || true', shell=True, capture_output=True, text=True)
    return render_template('admin.html', result=result.stdout + result.stderr, view='connectivity')

if __name__ == '__main__':
    init_db(); app.run(host='0.0.0.0', port=5000)
