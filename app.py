from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
import uuid
from functools import wraps

app = Flask(__name__)
app.secret_key = 'supersecretkey'

UPLOAD_FOLDER = 'static/profile_pics'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def init_db():
    if not os.path.exists('users.db'):
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
                -- profile_pic TEXT   # <-- REMOVE this line if you want to remove from DB
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                status TEXT DEFAULT 'open',
                close_reason TEXT,
                closed_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id INTEGER,
                sender TEXT,
                message TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(ticket_id) REFERENCES tickets(id)
            )
        ''')
        conn.commit()
        conn.close()
    else:
        # Auto-upgrade: add missing columns if needed
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in c.fetchall()]
        if 'created_at' not in columns:
            c.execute("ALTER TABLE users ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
        if 'last_login' not in columns:
            c.execute("ALTER TABLE users ADD COLUMN last_login TIMESTAMP")
        if 'profile_pic' not in columns:
            c.execute("ALTER TABLE users ADD COLUMN profile_pic TEXT")
        conn.commit()
        conn.close()

init_db()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            # Use the endpoint name as the page name for the flash message
            page = request.endpoint.replace('_', ' ').title() if request.endpoint else "this page"
            flash(f'Please login to view the {page}!', 'flash-error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@login_required
def home():
    return render_template('home.html', username=session.get('username'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'username' in session:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if not username or not password:
            flash("Username and password cannot be empty!", "flash-error")
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password)
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            session['username'] = username
            flash("Registered successfully!", "flash-success")
            return redirect(url_for('home'))
        except sqlite3.IntegrityError:
            flash("Username already taken!", "flash-error")
            return redirect(url_for('register'))
        finally:
            conn.close()
    return render_template('register.html', username=session.get('username'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Admin login check
        if username == 'Admin' and password == 'SamandOnekill':
            session['admin_logged_in'] = True
            flash('Admin login successful!', 'flash-success')
            return redirect(url_for('admin_dashboard'))
        # Normal user login
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user[0], password):
            session['username'] = username
            flash('Login successful!', 'flash-success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password!', 'flash-error')
            return redirect(url_for('login'))
    return render_template('login.html', username=session.get('username'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('admin_logged_in', None)
    flash('You have been logged out.', 'flash-success')
    return redirect(url_for('login'))

# Add admin dashboard route to prevent error if accessed
@app.route('/admin_dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        flash('Admin access required.', 'flash-error')
        return redirect(url_for('login'))
    return render_template('admin_dashboard.html', username='Admin')

@app.route('/plans')
@login_required
def plans():
    return render_template('plans.html', username=session.get('username'))

@app.route('/discord')
@login_required
def discord():
    return redirect("https://discord.gg/YOUR_SERVER_LINK")  # Replace with actual invite

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    username = session.get('username')
    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    if request.method == 'POST':
        # Only handle password change
        if (
            request.form.get('current_password') or
            request.form.get('new_password') or
            request.form.get('confirm_password')
        ):
            current_password = request.form.get('current_password', '')
            new_password = request.form.get('new_password', '')
            confirm_password = request.form.get('confirm_password', '')
            if not current_password or not new_password or not confirm_password:
                flash('All password fields are required.', 'flash-error')
            else:
                c.execute('SELECT password FROM users WHERE username = ?', (username,))
                user = c.fetchone()
                if user and check_password_hash(user[0], current_password):
                    if new_password == confirm_password:
                        hashed_new = generate_password_hash(new_password)
                        c.execute('UPDATE users SET password = ? WHERE username = ?', (hashed_new, username))
                        conn.commit()
                        flash('Password updated successfully!', 'flash-success')
                    else:
                        flash('New passwords do not match.', 'flash-error')
                else:
                    flash('Current password is incorrect.', 'flash-error')
    conn.close()
    return render_template('profile.html', username=username)

@app.route('/dashboard')
@login_required
def dashboard():
    username = session.get('username')
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    # Fetch user info
    c.execute("SELECT created_at, last_login FROM users WHERE username = ?", (username,))
    user_row = c.fetchone()
    created_at = user_row[0] if user_row else None
    last_login = user_row[1] if user_row else None
    # Fetch ticket stats
    c.execute("SELECT COUNT(*) FROM tickets WHERE username = ?", (username,))
    total_tickets = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM tickets WHERE username = ? AND status = 'open'", (username,))
    open_tickets = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM tickets WHERE username = ? AND status = 'closed'", (username,))
    closed_tickets = c.fetchone()[0]
    conn.close()
    return render_template(
        'dashboard.html',
        username=username,
        created_at=created_at,
        last_login=last_login,
        total_tickets=total_tickets,
        open_tickets=open_tickets,
        closed_tickets=closed_tickets
    )

@app.route('/contact', methods=['GET', 'POST'])
@login_required
def contact():
    if request.method == 'POST':
        username = session.get('username')
        message = request.form.get('message', '').strip()
        if message:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            # Create a new ticket for this message
            c.execute("INSERT INTO tickets (username) VALUES (?)", (username,))
            ticket_id = c.lastrowid
            c.execute("INSERT INTO messages (ticket_id, sender, message) VALUES (?, ?, ?)", (ticket_id, username, message))
            conn.commit()
            conn.close()
            flash('Your support ticket has been submitted!', 'flash-success')
            return redirect(url_for('contact'))
        else:
            flash('Message cannot be empty.', 'flash-error')
    return render_template('contact.html', username=session.get('username'))

@app.before_request
def update_last_login():
    if 'username' in session and request.endpoint not in ['static']:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT last_login FROM users WHERE username = ?", (session['username'],))
        row = c.fetchone()
        if row is not None:
            c.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE username = ?", (session['username'],))
            conn.commit()
        conn.close()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

