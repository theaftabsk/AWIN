from flask import Flask, render_template, request, redirect, session
import json, smtplib, ssl, random, os
from email.message import EmailMessage

app = Flask(__name__)
app.secret_key = 'your_secret_key'

OTP_STORE = {}  # Temporarily stores OTPs by email

# ========== UTILITIES ==========

def send_otp_email(receiver, otp):
    email_sender = "afc214982@gmail.com"
    app_password = "aqdcdiqbmkuvuqyj"
    subject = "AWIN OTP Verification"
    body = f"Your OTP code is: {otp}"

    em = EmailMessage()
    em['From'] = email_sender
    em['To'] = receiver
    em['Subject'] = subject
    em.set_content(body)

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
        smtp.login(email_sender, app_password)
        smtp.send_message(em)

def update_online_status(email, status):
    updated = []
    try:
        with open('users.json', 'r') as f:
            for line in f:
                user = json.loads(line.strip())
                if user.get('email') == email:
                    user['online'] = status
                updated.append(user)
        with open('users.json', 'w') as f:
            for user in updated:
                f.write(json.dumps(user) + '\n')
    except:
        pass

def update_user_field(email, field, value):
    updated = []
    try:
        with open('users.json', 'r') as f:
            for line in f:
                user = json.loads(line.strip())
                if user.get('email') == email:
                    user[field] = value
                updated.append(user)
        with open('users.json', 'w') as f:
            for user in updated:
                f.write(json.dumps(user) + '\n')
    except:
        pass

# ========== MAIN ROUTES ==========

@app.route('/')
def index():
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm = request.form['confirm']

        if password != confirm:
            return 'Password and Confirm Password do not match.'

        otp = str(random.randint(100000, 999999))
        OTP_STORE[email] = {'otp': otp, 'password': password}
        send_otp_email(email, otp)
        return render_template('otp.html', email=email)

    return render_template('register.html')

@app.route('/otp', methods=['GET', 'POST'])
def otp():
    if request.method == 'POST':
        email = request.form.get('email')
        otp_input = request.form.get('otp')

        if email in OTP_STORE and OTP_STORE[email]['otp'] == otp_input:
            with open('users.json', 'a') as f:
                json.dump({
                    'email': email,
                    'password': OTP_STORE[email]['password'],
                    'status': 'Active',
                    'balance': 0,
                    'online': False
                }, f)
                f.write("\n")
            session['user'] = email
            del OTP_STORE[email]
            update_online_status(email, True)
            return redirect('/home')
        else:
            return '❌ Invalid OTP!'
    return redirect('/register')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        try:
            with open('users.json', 'r') as f:
                for line in f:
                    user = json.loads(line.strip())
                    if user.get('email') == email and user.get('password') == password:
                        session['user'] = email
                        update_online_status(email, True)
                        return redirect('/home')
        except FileNotFoundError:
            pass

        return '❌ Login failed!'
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user' in session:
        update_online_status(session['user'], False)
        session.pop('user')
    return redirect('/login')

@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        email = request.form['email']
        otp = str(random.randint(100000, 999999))
        OTP_STORE[email] = {'otp': otp}
        send_otp_email(email, otp)
        return render_template('reset.html', email=email)
    return render_template('forgat.html')

@app.route('/reset', methods=['POST'])
def reset():
    email = request.form['email']
    otp_input = request.form['otp']
    new_password = request.form['new_password']

    if email in OTP_STORE and OTP_STORE[email]['otp'] == otp_input:
        new_lines = []
        try:
            with open('users.json', 'r') as f:
                for line in f:
                    user = json.loads(line.strip())
                    if user.get('email') == email:
                        user['password'] = new_password
                    new_lines.append(json.dumps(user))
            with open('users.json', 'w') as f:
                for line in new_lines:
                    f.write(line + '\n')
            del OTP_STORE[email]
            return redirect('/login')
        except:
            return 'Something went wrong!'
    return '❌ Invalid OTP!'

@app.route('/home')
def home():
    if 'user' in session:
        email = session['user']
        balance, who_plays, banner = 0, '', ''
        try:
            with open('users.json', 'r') as f:
                for line in f:
                    user = json.loads(line.strip())
                    if user.get('email') == email:
                        balance = user.get('balance', 0)
                        break
            with open('admin_data.json', 'r') as f:
                data = json.load(f)
                who_plays = data.get('who_plays_text', '')
                banner = data.get('banner_text', '')
        except:
            pass
        return render_template('home.html', balance=balance, who_plays_text=who_plays, banner_text=banner)
    return redirect('/login')

@app.route('/wallet')
def wallet():
    if 'user' in session:
        email = session['user']
        balance = 0
        try:
            with open('users.json', 'r') as f:
                for line in f:
                    user = json.loads(line.strip())
                    if user.get('email') == email:
                        balance = user.get('balance', 0)
                        break
        except:
            pass
        return render_template('wallet.html', balance=balance)
    return redirect('/login')

@app.route('/profile')
def profile():
    if 'user' in session:
        email = session['user']
        name = email.split('@')[0].capitalize()
        balance = 0
        status = 'Unknown'
        try:
            with open('users.json', 'r') as f:
                for line in f:
                    user = json.loads(line.strip())
                    if user.get('email') == email:
                        balance = user.get('balance', 0)
                        status = user.get('status', 'Active')
                        break
        except:
            pass
        return render_template('profile.html', name=name, balance=balance, status=status)
    return redirect('/login')

# ========== ADMIN PANEL ==========

@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if email == 'Aftab' and password == '12345678':
            session['admin'] = True
            return redirect('/admin/dashboard')
        return '❌ Invalid admin credentials!'
    return render_template('admin.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin' in session:
        return render_template('admin_dashboard.html')
    return redirect('/admin')

@app.route('/admin/users')
def admin_users():
    if 'admin' in session:
        users = []
        try:
            with open('users.json', 'r') as f:
                for line in f:
                    users.append(json.loads(line.strip()))
        except:
            pass
        return render_template('users.html', users=users)
    return redirect('/admin')

@app.route('/admin/suspend', methods=['POST'])
def suspend_user():
    if 'admin' in session:
        email = request.form['email']
        update_user_field(email, 'status', 'Suspended')
        return redirect('/admin/users')
    return redirect('/admin')

@app.route('/admin/unsuspend', methods=['POST'])
def unsuspend_user():
    if 'admin' in session:
        email = request.form['email']
        update_user_field(email, 'status', 'Active')
        return redirect('/admin/users')
    return redirect('/admin')

if __name__ == '__main__':
    app.run(debug=True)
