from flask import Flask, render_template, request, redirect, session, url_for
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Configure MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'password123@'
app.config['MYSQL_DB'] = 'notes'

mysql = MySQL(app)

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email=%s", [email])
        user = cur.fetchone()
        cur.close()

        if user and check_password_hash(user[3], password):  # Assuming password is at index 3
            session['user_id'] = user[0]  # Assuming user_id is at index 0
            return redirect(url_for('dashboard'))
        else:
            return 'Invalid credentials'
    
    return render_template('login.html')

# Signup Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        hashed_password = generate_password_hash(password, method='sha256')

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)", 
                    (username, email, hashed_password))
        mysql.connection.commit()
        cur.close()

        return redirect(url_for('login'))
    
    return render_template('signup.html')

# Dashboard Route (Show notes)
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    cur = mysql.connection.cursor()

    if request.method == 'POST':
        note = request.form['note']
        cur.execute("INSERT INTO notes (user_id, note) VALUES (%s, %s)", (user_id, note))
        mysql.connection.commit()

    cur.execute("SELECT * FROM notes WHERE user_id = %s", [user_id])
    notes = cur.fetchall()
    cur.close()

    return render_template('dashboard.html', notes=notes)

# Delete Note
@app.route('/delete_note/<int:id>')
def delete_note(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM notes WHERE id = %s", [id])
    mysql.connection.commit()
    cur.close()

    return redirect(url_for('dashboard'))

# Logout Route
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)
