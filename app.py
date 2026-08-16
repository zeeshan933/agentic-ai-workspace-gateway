from flask import Flask, render_template, redirect, url_for, request, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import pandas as pd
import os
from werkzeug.middleware.proxy_fix import ProxyFix  
import smtplib
from email.mime.text import MIMEText
import random
import string
import re
from urllib.parse import urlparse, urljoin
import requests
import uuid
from dotenv import load_dotenv  
load_dotenv()                   

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback-dev-key-do-not-use-in-prod')

# --- 1. PostgreSQL Database Configuration ---
# Format: postgresql://username:password@hostname:port/databasename
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Session & Cookie Configuration for Subdomain SSO ---
# app.config['SESSION_COOKIE_DOMAIN'] = '.resailab.com'    
cookie_domain = os.environ.get('COOKIE_DOMAIN')
if cookie_domain:
    app.config['SESSION_COOKIE_DOMAIN'] = cookie_domain
app.config['SESSION_COOKIE_SECURE'] = True             
app.config['PERMANENT_SESSION_LIFETIME'] = 18000      

# Email Configuration for OTP 
MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Database Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    session_token = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))

    def get_id(self):
        return self.session_token

# --- NEW: System Config Model for tracking Upload Locks ---
class SystemConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(200), nullable=False)

@login_manager.user_loader
def load_user(session_token):
    return User.query.filter_by(session_token=session_token).first()

# --- Helper Functions ---
def send_otp_email(to_email, otp):
    # [Email logic remains the same]
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head><meta charset="UTF-8"></head>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #121212; padding: 40px 20px; margin: 0;">
        <table width="100%" cellpadding="0" cellspacing="0" style="max-width: 500px; margin: 0 auto; background-color: #1e1e1e; border-radius: 16px; border: 1px solid #333333;">
            <tr>
                <td style="padding: 40px;">
                    <h2 style="color: #ffffff; text-align: center; margin-top: 0; margin-bottom: 24px;">Password Reset Request</h2>
                    <p style="color: #cccccc; font-size: 16px; line-height: 1.5; margin-bottom: 24px;">
                        We received a request to reset the password for your AI Workspace Gateway account. Please use the verification code below to set a new password:
                    </p>
                    <div style="text-align: center; margin-bottom: 30px;">
                        <span style="display: inline-block; background-color: #2a2a2a; color: #6366f1; font-size: 28px; font-weight: bold; padding: 16px 32px; border-radius: 12px; letter-spacing: 6px; border: 1px solid #444;">
                            {otp}
                        </span>
                    </div>
                </td>
            </tr>
        </table>
    </body>
    </html>
    """
    msg = MIMEText(html_body, 'html')
    msg['Subject'] = 'Workspace Gateway - Password Reset OTP'
    msg['From'] = MAIL_USERNAME
    msg['To'] = to_email

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        server.sendmail(MAIL_USERNAME, to_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False

# --- Routes ---
@app.route('/')
def home():
    return redirect(url_for('dashboard'))

@app.after_request
def add_cache_control_headers(response):
    """
    Force the browser to never cache dynamic pages.
    This ensures the UI always reflects the current session state.
    """
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response



# Helper function to prevent Open Redirects
def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

@app.route('/login', methods=['GET', 'POST'])
# @limiter.limit("5 per minute")  # Highly recommended: implement Flask-Limiter here
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # 1. Prevent unnecessary database hits for empty submissions
        if not username or not password:
            flash('Invalid credentials', 'error')
            return render_template('login.html')

        user = User.query.filter_by(username=username).first()
        
        # 2. Prevent Timing Attacks (Username Enumeration)
        if user:
            is_valid_password = check_password_hash(user.password_hash, password)
        else:
            # If the user isn't found, we still run the hashing algorithm against a dummy hash.
            # This ensures the server takes the exact same amount of time to respond, 
            # preventing attackers from guessing valid usernames based on response times.
            check_password_hash('scrypt:32768:8:1$dummy$hash', password) 
            is_valid_password = False
        
        if user and is_valid_password:
            login_user(user)
            session.permanent = True  
            
            # 3. Open Redirect Protection
            next_page = request.args.get('next')
            if next_page and not is_safe_url(next_page):
                return abort(400) # Reject malicious redirect attempts
                
            return redirect(next_page or url_for('dashboard'))
        else:
            # 4. Generic Error Messages
            flash('Invalid credentials', 'error')
            
    return render_template('login.html')

@app.route('/auth/verify')
def verify_auth():
    if current_user.is_authenticated:
        return "OK", 200     
    else:
        return "Unauthorized", 401 

@app.route('/logout')
@login_required
def logout():
    current_user.session_token = str(uuid.uuid4())
    db.session.commit()
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    host_identity = request.host.split(':')[0]
    
    # Strip "dashboard." from the URL so it becomes just "resailab.com"
    if host_identity.startswith('dashboard.'):
        base_domain = host_identity.replace('dashboard.', '', 1)
    else:
        base_domain = host_identity
        
    ollama_is_online = False
    
    # 1. THE INTERNAL PING (Docker Network)
    # Using 'ollama' instead of '127.0.0.1' so Docker routes it to the correct container.
    try:
        internal_response = requests.get('http://ollama:11434/', timeout=1)
        if internal_response.status_code == 200 and "Ollama is running" in internal_response.text:
            ollama_is_online = True
    except requests.exceptions.RequestException as e:
        print(f"Internal Ping Failed: {e}") # Helpful for debugging Docker network issues
        pass

    # 2. THE PUBLIC PING (Fallback)
    if not ollama_is_online:
        ollama_url = f"https://ollama.{base_domain}"
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'
            }
            
            # allow_redirects=False prevents Python from getting tricked by login pages
            response = requests.get(ollama_url, headers=headers, timeout=4, verify=False, allow_redirects=False)
            
            if response.status_code == 200 and "Ollama is running" in response.text:
                ollama_is_online = True
            else:
                print(f"Public Ping Failed check. Status: {response.status_code}, Text seen: {response.text[:100]}")
                
        except requests.exceptions.RequestException as e:
            print(f"Public Ping Failed completely: {e}")
        
    return render_template(
        'index.html', 
        domain_suffix=base_domain, 
        is_admin=current_user.is_admin,
        ollama_status=ollama_is_online 
    )
# --- Admin Routes ---
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_panel():
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST' and 'signup' in request.form:
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # 1. Check if username already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            
        # 2. Check if email already exists
        elif User.query.filter_by(email=email).first():
            flash('Email already exists.', 'error')
            
        # 3. If both are clear, try to create the user
        else:
            try:
                hashed_password = generate_password_hash(password)
                new_user = User(username=username, email=email, password_hash=hashed_password)
                db.session.add(new_user)
                db.session.commit()
                flash(f'User {username} created successfully!', 'success')
            except Exception as e:
                # Catch any unexpected database errors (like constraints) to prevent 500 crash
                db.session.rollback()
                flash('An internal error occurred. Could not create user.', 'error')
            
    return render_template('admin.html')

# --- 2. NEW: Manage All Users Page ---
@app.route('/admin/users')
@login_required
def manage_users():
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    # You will need to create a 'manage_users.html' template to render this list
    return render_template('manage_users.html', users=users)

@app.route('/admin/user/edit/<int:id>', methods=['POST'])
@login_required
def edit_user(id):
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
        
    user = User.query.get_or_404(id)
    user.username = request.form.get('username', user.username)
    user.email = request.form.get('email', user.email)
    user.is_admin = True if request.form.get('is_admin') == 'on' else False
    
    db.session.commit()
    flash(f'User {user.username} updated successfully.', 'success')
    return redirect(url_for('manage_users'))

@app.route('/admin/user/delete/<int:id>', methods=['POST'])
@login_required
def delete_user(id):
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
        
    if current_user.id == id:
        flash('You cannot delete your own admin account!', 'error')
        return redirect(url_for('manage_users'))
        
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    flash(f'User {user.username} has been deleted.', 'success')
    return redirect(url_for('manage_users'))


# --- 3. UPDATED: Excel Upload (50 Limit, 1 Hour Lock, Crash Protection & Format Validation) ---
@app.route('/admin/upload', methods=['POST'])
@login_required
def upload_users():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
        
    # Check if the upload lock is active
    lock_record = SystemConfig.query.filter_by(key='excel_upload_lock').first()
    if lock_record:
        lock_time = datetime.fromisoformat(lock_record.value)
        if datetime.now() < lock_time:
            time_left = int((lock_time - datetime.now()).total_seconds() / 60)
            flash(f'Upload is locked. Please wait {time_left} minutes before uploading again.', 'error')
            return redirect(url_for('admin_panel'))

    if 'file' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('admin_panel'))
        
    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('admin_panel'))
        
    if file and file.filename.endswith('.xlsx'):
        try:
            df = pd.read_excel(file, header=None)
            
            # Enforce max 50 users
            if len(df) > 50:
                df = df.head(50)
                flash('File contained more than 50 rows. Only the first 50 users were processed.', 'info')
                
            added_count = 0
            skipped_count = 0
            invalid_email_count = 0 # NEW: Keep track of bad formats
            
            # NEW: Standard email validation pattern
            email_pattern = re.compile(r'^[\w\.-]+@[\w\.-]+\.\w+$')
            
            for index, row in df.iterrows():
                username = str(row[0]).strip()
                email = str(row[1]).strip()
                
                # Skip empty rows to prevent database errors
                if pd.isna(username) or pd.isna(email) or username == 'nan' or email == 'nan' or not username or not email:
                    continue
                
                # NEW: Validate that Column B is actually an email!
                if not email_pattern.match(email):
                    invalid_email_count += 1
                    continue # Skip this row because it's junk data (like a course code)
                
                # 1. Check for BOTH existing username and existing email
                existing_user = User.query.filter(
                    (User.username == username) | (User.email == email)
                ).first()
                
                if existing_user:
                    skipped_count += 1
                    continue # Skip to the next row without crashing
                
                # 2. If it's a completely new user with a valid email, add them
                hashed_pw = generate_password_hash(username)
                new_user = User(username=username, email=email, password_hash=hashed_pw)
                db.session.add(new_user)
                added_count += 1
                    
            # Apply the 1-hour lock (only if we actually added people)
            if added_count > 0:
                new_lock_time = datetime.now() + timedelta(hours=1)
                if not lock_record:
                    lock_record = SystemConfig(key='excel_upload_lock', value=new_lock_time.isoformat())
                    db.session.add(lock_record)
                else:
                    lock_record.value = new_lock_time.isoformat()
                
            db.session.commit()
            
            # 3. Flash exact results including invalid emails
            if added_count == 0 and invalid_email_count > 0:
                flash(f'Upload failed: Found {invalid_email_count} invalid emails. Please check your Excel format (Col A=User, Col B=Email).', 'error')
            elif skipped_count > 0 or invalid_email_count > 0:
                flash(f'Added {added_count} users. {skipped_count} duplicates skipped, {invalid_email_count} invalid formats skipped. Locked for 1 hour.', 'warning')
            else:
                flash(f'Successfully added {added_count} users. Bulk upload is now locked for 1 hour.', 'success')

        except Exception as e:
            # Catch any database or file format errors to prevent the 500 crash screen
            db.session.rollback()
            flash('An error occurred while processing the file. Check for formatting issues.', 'error')
            print(f"Excel Upload Error: {e}") 
            
    else:
        flash('Invalid file format. Please upload a .xlsx file.', 'error')

    return redirect(url_for('admin_panel'))

# --- Forgot Password Routes ---
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            otp = ''.join(random.choices(string.digits, k=6))
            session['reset_otp'] = otp
            session['reset_email'] = email
            
            if send_otp_email(email, otp):
                return redirect(url_for('verify_otp'))
            else:
                flash('Failed to send email. Check configuration.', 'error')
        else:
            flash('This email is not registered in our records. Please contact the Admin.', 'error') 
            
    return render_template('forgot_password.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        user_otp = request.form.get('otp')
        if user_otp == session.get('reset_otp'):
            return redirect(url_for('reset_password'))
        else:
            flash('Invalid OTP', 'error')
    return render_template('verify_otp.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_email' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        new_password = request.form.get('password')
        hashed_password = generate_password_hash(new_password)
        
        user = User.query.filter_by(email=session['reset_email']).first()
        user.password_hash = hashed_password
        user.session_token = str(uuid.uuid4())
        
        db.session.commit()
        
        session.pop('reset_otp', None)
        session.pop('reset_email', None)
        flash('Password reset successfully. Please log in.', 'success')
        return redirect(url_for('login'))
        
    return render_template('reset_password.html')

# --- Move this ENTIRE block OUTSIDE the __main__ block ---
with app.app_context():
    # This will automatically create all tables in Postgres if they do not exist
    db.create_all()

    if not User.query.filter_by(username='admin').first():
        admin_pw = generate_password_hash('admin123')
        admin = User(username='admin', email='resailab@gmail.com', password_hash=admin_pw, is_admin=True)
        db.session.add(admin)
        db.session.commit()
        print("Default admin created: admin / admin123")

# --- Keep this at the very bottom for local testing only ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
