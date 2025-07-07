from flask import Flask, render_template, request, redirect, session
import json, smtplib, ssl, random, os
from email.message import EmailMessage

app = Flask(__name__)
app.secret_key = 'your_secret_key'

OTP_STORE = {}

# ================= MAIN ROUTES =================

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
                    'online': True
                }, f)
                f.write("\n")
            session['user'] = email
            del OTP_STORE[email]
            return redirect('/home')
        else:
            return 'Invalid OTP!'
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
                    if user['email'] == email and user['password'] == password:
                        session['user'] = email
                        update_online_status(email, True)
                        return redirect('/home')
        except FileNotFoundError:
            pass
        return 'Login failed!'
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
    return render_template('forgot.html')

@app.route('/reset', methods=['POST'])
def reset():
    email = request.form['email']
    otp_input = request.form['otp']
    new_password = request.form['new_password']

    if email in OTP_STORE and OTP_STORE[email]['otp'] == otp_input:
        updated = []
        with open('users.json', 'r') as f:
            for line in f:
                user = json.loads(line.strip())
                if user['email'] == email:
                    user['password'] = new_password
                updated.append(user)
        with open('users.json', 'w') as f:
            for user in updated:
                f.write(json.dumps(user) + '\n')
        del OTP_STORE[email]
        return redirect('/login')
    return 'Invalid OTP'

@app.route('/home')
def home():
    if 'user' in session:
        email = session['user']
        balance, banner, who_plays = 0, '', ''
        try:
            with open('users.json', 'r') as f:
                for line in f:
                    user = json.loads(line.strip())
                    if user['email'] == email:
                        balance = user['balance']
                        break
            with open('admin_data.json', 'r') as f:
                data = json.load(f)
                banner = data.get('banner_text', '')
                who_plays = data.get('who_plays_text', '')
        except:
            pass
        return render_template('home.html', balance=balance, banner_text=banner, who_plays_text=who_plays)
    return redirect('/login')

@app.route('/wallet')
def wallet():
    if 'user' in session:
        email = session['user']
        balance = get_user_balance(email)
        return render_template('wallet.html', balance=balance)
    return redirect('/login')

@app.route('/profile')
def profile():
    if 'user' in session:
        email = session['user']
        name = email.split('@')[0].capitalize()
        balance, status = 0, 'Unknown'
        with open('users.json', 'r') as f:
            for line in f:
                user = json.loads(line.strip())
                if user['email'] == email:
                    balance = user['balance']
                    status = user['status']
                    break
        return render_template('profile.html', name=name, balance=balance, status=status)
    return redirect('/login')

# ================= UTILITIES =================

def send_otp_email(receiver, otp):
    sender = "afc214982@gmail.com"
    password = "aqdcdiqbmkuvuqyj"
    subject = "AWIN OTP Verification"
    body = f"Your OTP code is: {otp}"

    em = EmailMessage()
    em['From'] = sender
    em['To'] = receiver
    em['Subject'] = subject
    em.set_content(body)

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
        smtp.login(sender, password)
        smtp.send_message(em)

def update_online_status(email, status):
    updated = []
    with open('users.json', 'r') as f:
        for line in f:
            user = json.loads(line.strip())
            if user['email'] == email:
                user['online'] = status
            updated.append(user)
    with open('users.json', 'w') as f:
        for user in updated:
            f.write(json.dumps(user) + '\n')

def get_user_balance(email):
    with open('users.json', 'r') as f:
        for line in f:
            user = json.loads(line.strip())
            if user['email'] == email:
                return user['balance']
    return 0

if __name__ == '__main__':
    app.run(debug=True)
