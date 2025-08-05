from flask import Flask, request, redirect, render_template_string, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask import render_template
app = Flask(__name__)
app.secret_key = 'secret123'  # Required for session

# In-memory storage
users = {}  # {username: {"password": hashed_pw, "locked": False, "attempts": 0}}

# HTML Templates (for simplicity)


signup_page = '''
    <h2>Sign Up</h2>
    {% if msg %}<p style="color:red;">{{ msg }}</p>{% endif %}
    <form method="POST">
        Username: <input name="username"><br>
        Password: <input name="password" type="password"><br>
        <input type="submit" value="Sign Up">
    </form>
    <p>Already have an account? <a href="/login">Login</a></p>
'''

welcome_page = '''
    <h2>Welcome {{ user }}</h2>
    <p><a href="/logout">Logout</a></p>
'''

@app.route('/')
def index():
    if 'user' in session:
        return render_template_string(welcome_page, user=session['user'])
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    msg = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users:
            msg = 'Username already exists!'
        else:
            users[username] = {
                "password": generate_password_hash(password),
                "locked": False,
                "attempts": 0
            }
            return redirect(url_for('login'))
    return render_template_string(signup_page, msg=msg)

@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users.get(username)

        if not user:
            msg = 'User does not exist.'
        elif user['locked']:
            msg = 'Account is locked due to multiple failed login attempts.'
        elif not check_password_hash(user['password'], password):
            user['attempts'] += 1
            if user['attempts'] >= 3:
                user['locked'] = True
                msg = 'Account locked after 3 failed attempts.'
            else:
                msg = f'Incorrect password. Attempt {user["attempts"]}/3'
        else:
            user['attempts'] = 0  # reset on successful login
            session['user'] = username
            return redirect(url_for('index'))

    return render_template('login_page.html', msg=msg)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
