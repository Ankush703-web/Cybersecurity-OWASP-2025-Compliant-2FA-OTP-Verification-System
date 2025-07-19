from flask import Flask, render_template, request, redirect, session, flash
from twilio.rest import Client
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pyotp
import json
import os
import time
import secrets
import hashlib
from datetime import datetime
import logging

#onfigure file-based logging
logging.basicConfig(
    filename='logs/otp_activity.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


app = Flask(__name__)
app.secret_key = os.urandom(24)

#Flask-Limiter setup
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["5 per minute"]
)

#Load Twilio credentials
with open('static/details.json') as f:
    details = json.load(f)
    twilio_sid = details['twilio_account_sid']
    twilio_token = details['twilio_auth_token']
    twilio_phone = details['twilio_phone_number']

client = Client(twilio_sid, twilio_token)

def generate_totp_secret():
    return pyotp.random_base32()

def generate_recovery_codes(n=5):
    return [secrets.token_hex(6) for _ in range(n)]

def get_device_signature():
    ip = request.remote_addr or "0.0.0.0"
    user_agent = request.headers.get("User-Agent", "")
    return hashlib.sha256(f"{ip}:{user_agent}".encode()).hexdigest()

@app.after_request
def apply_security_headers(response):
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

@app.route('/', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def index():
    if request.method == 'POST':
        phone = request.form['phone']
        if not phone.startswith('+'):
            phone = '+91' + phone

        totp_secret = generate_totp_secret()
        session['phone'] = phone
        session['totp_secret'] = totp_secret
        session['otp_time'] = time.time()
        session['otp_failures'] = 0
        session['recovery_codes'] = generate_recovery_codes()

        totp = pyotp.TOTP(totp_secret)
        otp = totp.now()

        try:
            client.messages.create(
                body=f"Your OTP is {otp}. Do NOT share this code. It expires in 30 seconds.",
                from_=twilio_phone,
                to=phone
            )
            print(f"[INFO] OTP sent to {phone}: {otp}")
            return redirect('/verify')
        except Exception as e:
            print("Twilio error:", e)
            flash("Failed to send OTP.", "danger")
            return render_template('index.html')

    return render_template('index.html')

@app.route('/verify', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def verify():
    if request.method == 'POST':
        user_otp = request.form['otp']
        totp_secret = session.get('totp_secret')
        last_used_otp = session.get('last_used_otp')
        user_ip = request.remote_addr
        phone = session.get('phone')
        recovery_codes = session.get('recovery_codes', [])

        if not totp_secret:
            flash('Session expired. Please request a new OTP.', 'danger')
            return redirect('/')

        if time.time() - session.get('otp_time', 0) > 300:
            flash('OTP expired. Please request a new one.', 'danger')
            return redirect('/')

        if session.get('otp_failures', 0) >= 5:
            print(f"[LOCKOUT] {phone} locked out from IP {user_ip}")
            flash("Too many incorrect attempts. Try later.", "danger")
            return render_template('verify.html', success=False)

        if user_otp == last_used_otp:
            flash('OTP already used. Request a new one.', 'danger')
            logging.warning(f"OTP REUSE attempt for phone {phone} from IP {user_ip}")
            return render_template('verify.html', success=False)

        if user_otp in recovery_codes:
            recovery_codes.remove(user_otp)
            session['recovery_codes'] = recovery_codes
            session['device_signature'] = get_device_signature()
            flash("Authenticated via recovery code.", "warning")
            logging.warning(f"Recovery code used for phone {phone} from IP {user_ip}")
            return render_template("verify.html", success=True)

        totp = pyotp.TOTP(totp_secret)
        if totp.verify(user_otp, valid_window=1):
            session['last_used_otp'] = user_otp
            session.pop('totp_secret', None)
            session['otp_failures'] = 0
            session['device_signature'] = get_device_signature()
            session['authenticated'] = True
            flash('OTP Verified Successfully!', 'success')
            print(f"[SUCCESS] OTP verified for {phone} from {user_ip}")
            logging.info(f"OTP verified successfully for phone {phone} from IP {user_ip} with device {request.headers.get('User-Agent')}")
            return render_template('verify.html', success=True)
        else:
            session['otp_failures'] = session.get('otp_failures', 0) + 1
            print(f"[FAILED OTP] {phone}, IP: {user_ip}, Fail #: {session['otp_failures']}, Time: {datetime.now()}")
            flash('Invalid OTP. Please try again.', 'danger')
            logging.warning(f"OTP FAILED for phone {phone} from IP {user_ip} with device {request.headers.get('User-Agent')}, Fail #{session['otp_failures']}")

            if session['otp_failures'] == 4:
                flash('Warning: One more failure will lock you out.', 'warning')

            return render_template('verify.html', success=False)

    return render_template('verify.html', success=None)

@app.route('/mfa-setup')
def mfa_setup():
    session['authenticated'] = True
    if not session.get('authenticated'):
        flash('Login required for MFA setup.', 'danger')
        return redirect('/login')

    secret = generate_totp_secret()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name="user@example.com", issuer_name="SecureApp")

    import qrcode
    img = qrcode.make(uri)
    img.save("static/qr.png")

    session['totp_secret'] = secret
    session['recovery_codes'] = generate_recovery_codes()

    return render_template("show_qr.html", recovery_codes=session['recovery_codes'])

@app.route('/revoke-mfa')
def revoke_mfa():
    if not session.get('authenticated'):
        flash("You must be logged in.", "danger")
        return redirect('/login')

    session.pop('totp_secret', None)
    session.pop('recovery_codes', None)
    session.pop('last_used_otp', None)
    session.pop('device_signature', None)
    flash("MFA credentials revoked.", "info")
    return redirect('/')

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if not session.get('authenticated'):
        flash("Login required.", "danger")
        return redirect('/')

    current_sig = get_device_signature()
    stored_sig = session.get('device_signature')

    if current_sig != stored_sig:
        flash("New device or IP detected. Re-authentication required.", "warning")
        return redirect('/step-up-verify')

    if request.method == 'POST':
        flash("Password changed successfully.", "success")
        return redirect('/')

    return render_template('change_password.html')

@app.route('/step-up-verify', methods=['GET', 'POST'])
def step_up_verify():
    if request.method == 'POST':
        user_otp = request.form['otp']
        totp_secret = session.get('totp_secret')

        if not totp_secret:
            flash("OTP expired. Please start over.", "danger")
            return redirect('/')

        totp = pyotp.TOTP(totp_secret)
        if totp.verify(user_otp, valid_window=1):
            session['device_signature'] = get_device_signature()
            session.pop('totp_secret', None)
            flash("Step-up authentication complete.", "success")
            logging.info(f"Step-up verification success for phone {session.get('phone')} from IP {request.remote_addr}")
            return redirect('/change-password')
        else:
            flash("Invalid OTP. Try again.", "danger")
            return render_template('verify.html', success=False)

    return render_template('verify.html', success=None)

if __name__ == '__main__':
    app.run(debug=True)
