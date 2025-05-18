from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from config import Config
from utils.auth_utils import hash_password, check_password
from utils.totp_utils import generate_totp_secret, verify_totp
import pyotp
import qrcode
import io
import base64
import re

# Initialize app
app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db = SQLAlchemy(app)  
jwt = JWTManager(app)

# Database model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    otp_secret = db.Column(db.String(64), nullable=False)

# Helper function to validate password
def is_valid_password(password):
    return re.match(r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[\\W_]).{8,}$", password)

# Route: Home
@app.route('/')
def home():
    return redirect(url_for('login'))

# Route: Start (Register or Login)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if not user:
            # Validate new user password
            if not is_valid_password(password):
                error_msg = "Password must be at least 8 characters long and include uppercase, lowercase, a number, and a special character."
                return render_template("login.html", error=error_msg)


            # New user registration
            otp_secret = generate_totp_secret()
            password_hash = hash_password(password)
            user = User(email=email, password_hash=password_hash, otp_secret=otp_secret)
            db.session.add(user)
            db.session.commit()

            session['email'] = email

            # Generate QR Code
            uri = pyotp.TOTP(otp_secret).provisioning_uri(name=email, issuer_name="SecureAuth")
            qr = qrcode.make(uri)
            buf = io.BytesIO()
            qr.save(buf)
            img_base64 = base64.b64encode(buf.getvalue()).decode()

            return render_template("qr_display.html", qr_code_url=f"data:image/png;base64,{img_base64}", next_step="/verify-otp")

        # Existing user login attempt
        if check_password(password, user.password_hash):
            session['email'] = email
            return render_template("dashboard.html")
        else:
            return render_template("invalid_credentials.html")

    return render_template("login.html")

@app.route('/logout')
def logout():
    session.clear()  # Clears the session data (user login data)
    return redirect(url_for('login'))  # Redirect to the login page or home

# Route: OTP Verification
@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        otp = request.form['otp']
        email = session.get('email')
        user = User.query.filter_by(email=email).first()
        if user and verify_totp(user.otp_secret, otp):
            access_token = create_access_token(identity=email)
            return render_template("registration_success.html", token=access_token)
        return render_template("invalid_otp.html")

    return render_template("otp_verify.html")

# Initialize DB and Run App
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
