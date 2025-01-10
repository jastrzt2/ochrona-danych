import base64
import datetime
import os
import random
import time
from flask import Flask, abort, request, session, redirect, url_for, render_template
import markdown
import pyotp
from bleacher import bleach_html
from db import count_password_reset_attempts, count_send_reset_email_attempts, create_note, delete_note, delete_reset_token, get_latest_notes, get_latest_users, get_login_attempts, get_note_by_id, get_notes_by_user, get_unique_ips, get_user_basic_data_by_id, get_user_id_by_email, get_user_id_by_reset_token, get_user_note_by_id, get_user_totp_secret, has_exceeded_login_attempts, init_db, get_user_by_username, create_user, get_user_by_id, is_email_in_database, record_login_attempt, record_password_reset_attempt, record_send_reset_email_attempt, reset_password_update_user_data, save_reset_token, update_note, update_user_password
from authorization import hash_token, verify_password
from qrcode_generator import generate_qr_code
from request_informations import get_ip_info
from signer import verify_sign
from validate_requests import validate_change_password, validate_forgot_password, validate_login_inputs, validate_note_create_or_edit, validate_register_inputs, validate_reset_password
import secrets
from flask_wtf import CSRFProtect

init_db()
app = Flask(__name__)
app.secret_key = os.urandom(24)
app.permanent_session_lifetime = datetime.timedelta(minutes=30)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
csrf = CSRFProtect(app)

init_db()
        
HONEYPOT_ROUTES = ['register', 'login', 'add_note', 'edit_note', 'change_password', 'forgot_password', 'reset_password']

CSP_POLICY = {
    'default-src': ["'self'"],
    'img-src': ["'self'"],
    'style-src': ["'self'"],
    'script-src': ["'self'"],
}


@app.after_request
def set_csp(response):
    response.headers['Content-Security-Policy'] = CSP_POLICY
    return response

@app.before_request
def before_request_actions():
    if 'user_id' in session:
        session.permanent = True

    if request.method == 'POST':
        endpoint = request.endpoint
        if endpoint in HONEYPOT_ROUTES:
            honeypot = request.form.get('honeypot', '')
            if honeypot:
                abort(403)

@app.route('/')
def index():
    notes = get_latest_notes(limit=5)
    users = get_latest_users(limit=5)

    user_id = session.get('user_id')
    current_user = None
    login_attempts = []
    unique_ips = []

    if user_id:
        current_user = get_user_basic_data_by_id(user_id)
        if current_user:
            login_attempts = get_login_attempts(user_id, limit=10)
            unique_ips = get_unique_ips(user_id)

    return render_template('index.html', notes=notes, users=users, current_user=current_user, login_attempts=login_attempts, unique_ips=unique_ips)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        min_time = 2.0
        start_time = time.time()
        random_sleep_time = random.uniform(0, 1)
        min_time = min_time + random_sleep_time
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        repeated_password = request.form.get('repeat_password', '').strip()
        email = request.form.get('email', '').strip()
        
        if not username or not password or not repeated_password or not email:
            sleep_to_meet_min_time(min_time, time.time() - start_time)
            return render_template('register.html', error="All fields are required")
        
        error = validate_register_inputs(username, password, repeated_password, email)
        if error: 
            sleep_to_meet_min_time(min_time, time.time() - start_time)
            return render_template('register.html', error=error)
        
        if get_user_by_username(username):
            sleep_to_meet_min_time(min_time, time.time() - start_time)
            return render_template('register.html', error="User with this username already exists")
        if is_email_in_database(email):
            sleep_to_meet_min_time(min_time, time.time() - start_time)
            return render_template('register.html', error="User with this email already exists")

        ip_address = request.remote_addr
        login_time = datetime.datetime.now()
        request_info = get_ip_info(ip_address)

        country_name = request_info.get('country_name', 'Unknown')
        country_code = request_info.get('country_code2', 'Unknown')
        isp = request_info.get('isp', 'Unknown')
        city = request_info.get('city', 'Unknown')

        totp_secret = pyotp.random_base32()
        totp = pyotp.TOTP(totp_secret)
        provisioning_uri = totp.provisioning_uri(name=username, issuer_name="Projekt Ochrona danych")

        qr_code_base64 = generate_qr_code(provisioning_uri)

        create_user(username, password, email, totp_secret)
        user_id = get_user_by_username(username)[0]
        session['user_id'] = user_id
        record_login_attempt(user_id, ip_address, country_name, country_code, isp, city, login_time, True)

        
        sleep_to_meet_min_time(min_time, time.time() - start_time)
        return render_template('register_success.html', totp_secret=totp_secret, qr_code_base64=qr_code_base64)
    else:
        return render_template('register.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    ip_address = request.remote_addr
    login_time = datetime.datetime.now()
    request_info = get_ip_info(ip_address)
    country_name = request_info.get('country_name', 'Unknown')
    country_code = request_info.get('country_code2', 'Unknown')
    isp = request_info.get('isp', 'Unknown')
    city = request_info.get('city', 'Unknown')
    
    if request.method == 'POST':
        min_time = 1.0 
        start_time = time.time()
        random_sleep_time = random.uniform(0.0, 0.5)
        min_time = min_time + random_sleep_time
        time.sleep(random_sleep_time)
        
        if has_exceeded_login_attempts(ip_address):
            sleep_to_meet_min_time(min_time, time.time() - start_time)
            record_login_attempt(None, ip_address, country_name, country_code, isp, city, login_time, False)
            return render_template('login.html', error="Too many login attempts")
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        totp_token = request.form.get('totp', '').strip()

        if not username or not password or not totp_token:
            sleep_to_meet_min_time(min_time, time.time() - start_time)
            record_login_attempt(None, ip_address, country_name, country_code, isp, city, login_time, False)
            return render_template('login.html', error="All fields are required")
        
        error = validate_login_inputs(username, password, totp_token)
        if error:
            sleep_to_meet_min_time(min_time, time.time() - start_time)
            record_login_attempt(None, ip_address, country_name, country_code, isp, city, login_time, False)
            return render_template('login.html', error=error)
        
        user = get_user_by_username(username)
        if user is None:
            sleep_to_meet_min_time(min_time, time.time() - start_time)
            record_login_attempt(None, ip_address, country_name, country_code, isp, city, login_time, False)
            return render_template('login.html', error="Invalid credentials")

        if not verify_password(password, user[4]):
            record_login_attempt(user[0], ip_address, country_name, country_code, isp, city, login_time, False)
            sleep_to_meet_min_time(min_time, time.time() - start_time)
            return render_template('login.html', error="Invalid credentials")
        
        totp_secret = get_user_totp_secret(user[0], password)
        totp = pyotp.TOTP(totp_secret)
        if not totp.verify(totp_token): 
            record_login_attempt(user[0], ip_address, country_name, country_code, isp, city, login_time, False)
            sleep_to_meet_min_time(min_time, time.time() - start_time)
            return render_template('login.html', error="Invalid credentials")

        session['user_id'] = user[0]
        record_login_attempt(user[0], ip_address, country_name, country_code, isp, city, login_time, True)
        
        sleep_to_meet_min_time(min_time, time.time() - start_time)
        return redirect(url_for('index'))
    else:
        return render_template('login.html')
    
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if not session.get('user_id'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        min_time = 1.0 #zakladam taki sam czas przetwarzania jak login
        start_time = time.time()
        random_sleep_time = random.uniform(0.0, 0.5)
        min_time = min_time + random_sleep_time
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        totp_token = request.form.get('totp', '').strip()

        error = validate_change_password(current_password, new_password, confirm_password)
        if error:
            sleep_to_meet_min_time(min_time, time.time() - start_time)
            return render_template('change_password.html', error=error)
            
        if not verify_password(current_password, get_user_by_id(session['user_id'])[4]):
            sleep_to_meet_min_time(min_time, time.time() - start_time)
            return render_template('change_password.html', error="Wrong current password")
        
        totp_secret = get_user_totp_secret(session['user_id']), current_password
        totp = pyotp.TOTP(totp_secret)
        if not totp.verify(totp_token):
            sleep_to_meet_min_time(min_time, time.time() - start_time)
            return render_template('change_password.html', error="Invalid TOTP code")
        
        update_user_password(session['user_id'], new_password, current_password)
        sleep_to_meet_min_time(min_time, time.time() - start_time)
        return redirect(url_for('index'))

    return render_template('change_password.html')


@app.route('/add_note', methods=['GET','POST'])
def add_note():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        min_time = 2.0 # dłuzsza notka będzie tyle przetwarzana, wiec to min time
        start_time = time.time()
        random_sleep_time = random.uniform(0.0, 0.5)
        min_time = min_time + random_sleep_time
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        password = request.form.get('password', '').strip()
        
        error = validate_note_create_or_edit(title, content, password)
        if error:
            sleep_to_meet_min_time(min_time, time.time() - start_time)
            return render_template('add_note.html', user_id=user_id, username=get_user_basic_data_by_id(user_id)[1], error=error)
        if not verify_password(password, get_user_by_id(user_id)[4]):
            sleep_to_meet_min_time(min_time, time.time() - start_time)
            return render_template('add_note.html', error="Wrong password")
        
        create_note( title, content, user_id, password)
        
        sleep_to_meet_min_time(min_time, time.time() - start_time)
        return redirect(url_for('index'))

    return render_template('add_note.html')

@app.route('/notes/<int:note_id>')
def show_note(note_id):
    user_id = session.get('user_id')
    if not user_id:
        return "User is not logged in", 401

    note = get_note_by_id(note_id)
    if not note:
        return "Note doesn't exist", 404
    
    owner = get_user_basic_data_by_id(note[4])
    public_key = owner[2]
    
    signature_valid = verify_sign(note[2], note[3], public_key)
    sign_base64 = base64.b64encode(note[3]).decode('utf-8')
    
    rendered = markdown.markdown(note[2], extensions=['extra', 'codehilite'])
    
    bleached_html = bleach_html(rendered)
    return render_template('show_note.html', signature_valid=signature_valid, 
                           note_id=note_id, title=note[1], 
                           content=bleached_html, sign=sign_base64, 
                           note_owner_id = note[4], 
                           current_user_id = user_id)


@app.route('/notes/<int:note_id>/edit', methods=['GET', 'POST'])
def edit_note(note_id):
    user_id = session.get('user_id')
    if not user_id:
        return "Unauthorized access.", 401

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        password = request.form.get('password', '')
        
        error = validate_note_create_or_edit(title, content, password)
        if error:
            return render_template('edit_note.html', error=error, note_id=note_id)
        
        if not verify_password(password, get_user_by_id(user_id)[4]):
            return render_template('edit_note.html', error="Wrong password")
        
        bleached_html = bleach_html(content)
        update_note(note_id, title, bleached_html, user_id, password)
        return redirect(url_for('show_note', note_id=note_id))  

    note = get_user_note_by_id(note_id, user_id)
    if not note:
        return "Note doesn't exist or action is unauthorized", 404

    return render_template('edit_note.html', note=note)

@app.route('/notes/<int:note_id>/delete', methods=['POST'])
def delete_note_endpoint(note_id):
    user_id = session.get('user_id')
    if not user_id:
        return "Unauthorized access.", 401

    delete_note(note_id, user_id)
    return redirect(url_for('index'))

@app.route('/user/<int:user_id>')
def user_page(user_id):
    user = get_user_basic_data_by_id(user_id)
    if not user:
        return "User not found", 404
    username = user[1]
    public_key = user[2]
    public_key_base64 = base64.b64encode(public_key).decode('utf-8')
    notes = get_notes_by_user(user_id)
    return render_template('user_page.html', public_key = public_key_base64, username=username, notes=notes)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        min_time = 2.0 # tak wysoki ze wzgledu na konieczność przegladania bazy danych przy generowaniu tokenu
        start_time = time.time()
        random_sleep_time = random.uniform(0.0, 1.0)
        min_time = min_time + random_sleep_time
        ip = request.remote_addr
        current_time = datetime.datetime.now()

        record_send_reset_email_attempt(ip, current_time)
        
        if count_send_reset_email_attempts(ip):
            sleep_to_meet_min_time(min_time, time.time() - start_time)
            return render_template('forgot_password.html', error="Too many password reset attempts. Please try again later.")
        
        email = request.form.get('email', '').strip()
        
        error = validate_forgot_password(email)
        if error: 
            sleep_to_meet_min_time(min_time, time.time() - start_time)
            return render_template('forgot_password.html', error=error)
        
        user_id = get_user_id_by_email(email)
        if not user_id:
            sleep_to_meet_min_time(min_time, time.time() - start_time)
            return render_template('forgot_password.html', message="Please check your email.")
        
        token = None
        while not token:
            potential_token = secrets.token_urlsafe(32)
            hashed_token = hash_token(potential_token)
            if not get_user_id_by_reset_token(hashed_token):
                token = potential_token
        
        hashed_token = hash_token(token)
        save_reset_token(user_id, hashed_token)
        
        reset_link = url_for('reset_password', token=token, _external=True)
        print(f"Resetowanie hasła dla użytkownika {email}: {reset_link}")

        sleep_to_meet_min_time(min_time, time.time() - start_time)
        return render_template('forgot_password.html', message="Please check your email.")
    
    return render_template('forgot_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    ip = request.remote_addr
    current_time = datetime.datetime.now()

    record_password_reset_attempt(ip, current_time)

    hashed_token = hash_token(token)
    user_id = get_user_id_by_reset_token(hashed_token)
    
    if count_password_reset_attempts(ip):
        return render_template('reset_password.html', error="Too many password reset attempts. Please try again later.")
    
    if not user_id:
        return render_template('reset_password.html', error="Invalid token")

    if request.method == 'POST':
    
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        error = validate_reset_password(new_password, confirm_password)
        if error: 
            return render_template('reset_password.html', error=error)

        delete_reset_token(token)
        
        username = get_user_by_id(user_id)[1]
        totp_secret = pyotp.random_base32()
        totp = pyotp.TOTP(totp_secret)
        provisioning_uri = totp.provisioning_uri(name=username, issuer_name="Projekt Ochrona danych")

        reset_password_update_user_data(user_id, new_password, totp_secret)

        qr_code_base64 = generate_qr_code(provisioning_uri)
        return render_template('reset_password_succes.html', totp_secret=totp_secret, qr_code_base64=qr_code_base64)
    return render_template('reset_password.html', token=token)

@app.route('/all_notes')
def all_notes():
    notes = get_latest_notes(limit=None) 
    return render_template('all_notes.html', notes=notes)


@app.route('/all_users')
def all_users():
    users = get_latest_users(limit=None) 
    return render_template('all_users.html', users=users)


def sleep_to_meet_min_time(min_time, elapsed_time):
    remaining_time = min_time - elapsed_time
    if remaining_time > 0:
        time.sleep(remaining_time)

if __name__ == '__main__':
    app.run(debug=False)