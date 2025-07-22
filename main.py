from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, make_response
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Regexp, Length, ValidationError
from datetime import datetime
import sqlite3
import re
import os
from pysnmp.hlapi import *
from functools import wraps
from flask_bcrypt import Bcrypt
import bleach
import requests
import pyotp
import qrcode
import base64
from io import BytesIO, StringIO
import logging
import csv

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'supersecurekey123456')
app.config['SESSION_COOKIE_SECURE'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes
bcrypt = Bcrypt(app)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Custom Jinja2 filter for ternary operation
def ternary_filter(value, true_val, false_val):
    return true_val if value else false_val

app.jinja_env.filters['ternary'] = ternary_filter

# Initialize SQLite database
def init_db():
    with sqlite3.connect('devices.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS pending_devices
                     (mac TEXT PRIMARY KEY, seen TEXT, switch_ip TEXT, port TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS mab_devices
                     (mac TEXT PRIMARY KEY, description TEXT, group_name TEXT, assigned_user TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (username TEXT PRIMARY KEY, password TEXT, role TEXT, totp_secret TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS settings
                     (key TEXT PRIMARY KEY, value TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS audit_log
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, username TEXT, role TEXT, action TEXT, details TEXT)''')
        # Insert initial data
        c.execute('INSERT OR IGNORE INTO pending_devices (mac, seen, switch_ip, port) VALUES (?, ?, ?, ?)',
                  ('AA:BB:CC:DD:EE:FF', '2025-07-12 09:32', '10.45.18.1', 'Gi1/0/10'))
        c.execute('INSERT OR IGNORE INTO pending_devices (mac, seen, switch_ip, port) VALUES (?, ?, ?, ?)',
                  ('11:22:33:44:55:66', '2025-07-12 09:45', '10.45.22.1', 'Gi1/0/11'))
        admin_password = bcrypt.generate_password_hash('StrongPassword123').decode('utf-8')
        approver_password = bcrypt.generate_password_hash('ApproverPass123').decode('utf-8')
        contributor_password = bcrypt.generate_password_hash('ContributorPass123').decode('utf-8')
        c.execute('INSERT OR IGNORE INTO users (username, password, role, totp_secret) VALUES (?, ?, ?, ?)',
                  ('admin', admin_password, 'Administrator', ''))
        c.execute('INSERT OR IGNORE INTO users (username, password, role, totp_secret) VALUES (?, ?, ?, ?)',
                  ('approver', approver_password, 'Approver', ''))
        c.execute('INSERT OR IGNORE INTO users (username, password, role, totp_secret) VALUES (?, ?, ?, ?)',
                  ('contributor', contributor_password, 'Contributor', ''))
        c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', ('snmp_community', 'public'))
        c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', ('ise_api_url', 'https://ise.example.com'))
        c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', ('ise_username', 'ise_user'))
        c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', ('ise_password', bcrypt.generate_password_hash('ise_pass').decode('utf-8')))
        conn.commit()

# Log user actions
def log_action(username, role, action, details):
    with sqlite3.connect('devices.db') as conn:
        c = conn.cursor()
        c.execute('INSERT INTO audit_log (timestamp, username, role, action, details) VALUES (?, ?, ?, ?, ?)',
                  (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), username, role, action, details))
        conn.commit()
    logger.info(f"Action logged: {username} ({role}) - {action}: {details}")

# Cisco ISE API integration
def cisco_ise_api_authorize(mac, group):
    with sqlite3.connect('devices.db') as conn:
        c = conn.cursor()
        c.execute('SELECT value FROM settings WHERE key IN (?, ?, ?)',
                  ('ise_api_url', 'ise_username', 'ise_password'))
        settings = c.fetchall()
        if len(settings) != 3:
            return {"status": "error", "message": "ISE settings not configured"}
        ise_url, ise_username, ise_password = [s[0] for s in settings]
    
    try:
        headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
        payload = {
            "ERSEndPoint": {
                "mac": mac,
                "groupId": group
            }
        }
        response = requests.post(
            f"{ise_url}/ers/config/endpoint",
            json=payload,
            auth=(ise_username, bcrypt.check_password_hash(ise_password, 'ise_pass') and 'ise_pass' or ise_password),
            headers=headers,
            verify=False
        )
        if response.status_code == 201:
            return {"status": "success", "message": f"Device {mac} authorized in group {group}"}
        else:
            return {"status": "error", "message": f"ISE API error: {response.text}"}
    except Exception as e:
        return {"status": "error", "message": f"ISE API request failed: {str(e)}"}

# SNMP function
def get_snmp_sysinfo(ip):
    try:
        with sqlite3.connect('devices.db') as conn:
            c = conn.cursor()
            c.execute('SELECT value FROM settings WHERE key = ?', ('snmp_community',))
            community = c.fetchone()[0] or 'public'

        sys_name_oid = '1.3.6.1.2.1.1.5.0'
        sys_location_oid = '1.3.6.1.2.1.1.6.0'
        result = {'name': 'SNMP Error', 'location': 'SNMP Error'}

        for oid, key in [(sys_name_oid, 'name'), (sys_location_oid, 'location')]:
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=1),
                UdpTransportTarget((ip, 161), timeout=1, retries=1),
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            )
            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
            if not errorIndication and not errorStatus:
                for varBind in varBinds:
                    result[key] = str(varBind[1])
            else:
                logger.error(f"SNMP error for {ip} ({key}): {errorIndication or errorStatus.prettyPrint()}")
    except Exception as e:
        logger.error(f"Fatal SNMP error for {ip}: {e}")
    return result

# Password complexity validator
def password_complexity(form, field):
    password = field.data
    if len(password) < 12:
        raise ValidationError('Password must be at least 12 characters long.')
    if not re.search(r'[A-Z]', password):
        raise ValidationError('Password must contain at least one uppercase letter.')
    if not re.search(r'[a-z]', password):
        raise ValidationError('Password must contain at least one lowercase letter.')
    if not re.search(r'[0-9]', password):
        raise ValidationError('Password must contain at least one digit.')
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise ValidationError('Password must contain at least one special character.')

# Forms
class AddDeviceForm(FlaskForm):
    mac = StringField('MAC Address', validators=[
        DataRequired(),
        Regexp(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', message="Invalid MAC address format")
    ])
    description = StringField('Description', validators=[DataRequired(), Length(min=3)])
    group = SelectField('Group', choices=[
        ('', '-- Select Group --'), 
        ('Printers', 'Printers'), 
        ('IoT_Meeting', 'IoT_Meeting'), 
        ('Mgmt_AP', 'Mgmt_AP'), 
        ('Mgmt_SW', 'Mgmt_SW')
    ], validators=[DataRequired()])
    submit = SubmitField('Add Device')

class AuthorizeDeviceForm(FlaskForm):
    mac = StringField('MAC Address', validators=[DataRequired()])
    group = SelectField('Group', choices=[
        ('Printers', 'Printers'), 
        ('IoT_Meeting', 'IoT_Meeting'), 
        ('Mgmt_AP', 'Mgmt_AP'), 
        ('Mgmt_SW', 'Mgmt_SW')
    ], validators=[DataRequired()])
    submit = SubmitField('Authorize')

class EditDeviceForm(FlaskForm):
    mac = StringField('MAC Address', validators=[DataRequired()], render_kw={"readonly": True})
    description = StringField('Description', validators=[DataRequired(), Length(min=3)])
    group = SelectField('Group', choices=[
        ('Printers', 'Printers'),
        ('IoT_Meeting', 'IoT_Meeting'),
        ('Mgmt_AP', 'Mgmt_AP'),
        ('Mgmt_SW', 'Mgmt_SW')
    ], validators=[DataRequired()])
    assigned_user = SelectField('Assigned User', choices=[], validators=[DataRequired()])
    submit = SubmitField('Save Changes')

class SettingsForm(FlaskForm):
    snmp_community = StringField('SNMP Community String', validators=[DataRequired()])
    ise_api_url = StringField('Cisco ISE API URL', validators=[DataRequired()])
    ise_username = StringField('Cisco ISE Username', validators=[DataRequired()])
    ise_password = PasswordField('Cisco ISE Password', validators=[DataRequired(), password_complexity])
    submit = SubmitField('Save Settings')

class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=12), password_complexity])
    role = SelectField('Role', choices=[
        ('Administrator', 'Administrator'),
        ('Approver', 'Approver'),
        ('Contributor', 'Contributor')
    ], validators=[DataRequired()])
    submit = SubmitField('Add User')

class EditUserForm(FlaskForm):
    role = SelectField('Role', choices=[
        ('Administrator', 'Administrator'),
        ('Approver', 'Approver'),
        ('Contributor', 'Contributor')
    ], validators=[DataRequired()])
    submit = SubmitField('Save Changes')

class TwoFactorForm(FlaskForm):
    totp_code = StringField('2FA Code', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify')

class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Old Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), password_complexity])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired()])
    submit = SubmitField('Change Password')

class TwoFactorSetupForm(FlaskForm):
    enable_2fa = BooleanField('Enable Two-Factor Authentication')
    submit = SubmitField('Save 2FA Settings')

# RBAC decorator
def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('logged_in'):
                return redirect(url_for('login'))
            user_role = session.get('role')
            if user_role not in roles:
                flash('Unauthorized access', 'error')
                log_action(session.get('username'), user_role, 'Unauthorized Access', f"Attempted access to {request.path}")
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# 2FA setup and verification
@app.route('/profile', methods=['GET', 'POST'])
@role_required('Administrator', 'Approver', 'Contributor')
def profile():
    password_form = ChangePasswordForm(prefix='password')
    two_factor_form = TwoFactorSetupForm(prefix='2fa')
    username = session.get('username')

    with sqlite3.connect('devices.db') as conn:
        c = conn.cursor()
        c.execute('SELECT password, totp_secret FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        current_password_hash, totp_secret = user[0], user[1]

        if password_form.validate_on_submit() and password_form.submit.data:
            if bcrypt.check_password_hash(current_password_hash, password_form.old_password.data):
                if password_form.new_password.data == password_form.confirm_password.data:
                    new_password_hash = bcrypt.generate_password_hash(password_form.new_password.data).decode('utf-8')
                    c.execute('UPDATE users SET password = ? WHERE username = ?', (new_password_hash, username))
                    conn.commit()
                    flash('Password updated successfully', 'success')
                    log_action(username, session.get('role'), 'Password Change', 'User changed their password')
                    return redirect(url_for('profile'))
                else:
                    flash('New passwords do not match', 'error')
            else:
                flash('Invalid old password', 'error')

        if two_factor_form.validate_on_submit() and two_factor_form.submit.data:
            if two_factor_form.enable_2fa.data:
                if not totp_secret:
                    new_totp_secret = pyotp.random_base32()
                    c.execute('UPDATE users SET totp_secret = ? WHERE username = ?', (new_totp_secret, username))
                    conn.commit()
                    totp_secret = new_totp_secret
                    log_action(username, session.get('role'), '2FA Enabled', 'Enabled 2FA and generated new TOTP secret')
                    flash('2FA enabled successfully', 'success')
            else:
                c.execute('UPDATE users SET totp_secret = ? WHERE username = ?', ('', username))
                conn.commit()
                totp_secret = ''
                log_action(username, session.get('role'), '2FA Disabled', 'Disabled 2FA')
                flash('2FA disabled successfully', 'success')
            return redirect(url_for('profile'))

    qr_code = None
    if totp_secret:
        totp = pyotp.TOTP(totp_secret)
        qr_uri = totp.provisioning_uri(name=username, issuer_name='Cisco ISE Device Portal')
        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(qr_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        qr_code = base64.b64encode(buffer.getvalue()).decode('utf-8')

    return render_template('profile.html', password_form=password_form, two_factor_form=two_factor_form, qr_code=qr_code, totp_secret=totp_secret)

@app.route('/2fa-verify', methods=['GET', 'POST'])
def two_factor_verify():
    if not session.get('pending_2fa'):
        return redirect(url_for('login'))
    form = TwoFactorForm()
    username = session.get('pending_2fa')
    if form.validate_on_submit():
        with sqlite3.connect('devices.db') as conn:
            c = conn.cursor()
            c.execute('SELECT totp_secret, role FROM users WHERE username = ?', (username,))
            user = c.fetchone()
            if not user:
                flash('User not found', 'error')
                log_action(username, 'Unknown', 'Login Failed', 'User not found')
                return redirect(url_for('login'))
            totp_secret, role = user
            if totp_secret and pyotp.TOTP(totp_secret).verify(form.totp_code.data):
                session['logged_in'] = True
                session['username'] = username
                session['role'] = role
                session.pop('pending_2fa', None)
                session.permanent = True
                log_action(username, role, 'Login Success', '2FA verified')
                return redirect(url_for('index', page='dashboard'))
            flash('Invalid 2FA code', 'error')
            log_action(username, role, 'Login Failed', 'Invalid 2FA code')
    return render_template('2fa_verify.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = bleach.clean(request.form.get('username'))
        password = request.form.get('password')
        with sqlite3.connect('devices.db') as conn:
            c = conn.cursor()
            c.execute('SELECT password, role, totp_secret FROM users WHERE username = ?', (username,))
            user = c.fetchone()
            if user and bcrypt.check_password_hash(user[0], password):
                if user[2]:  # totp_secret exists
                    session['pending_2fa'] = username
                    log_action(username, user[1], 'Login Attempt', 'Password verified, awaiting 2FA')
                    return redirect(url_for('two_factor_verify'))
                session['logged_in'] = True
                session['username'] = username
                session['role'] = user[1]
                session.permanent = True
                log_action(username, user[1], 'Login Success', 'Logged in without 2FA')
                return redirect(url_for('index', page='dashboard'))
            flash('Invalid credentials', 'error')
            log_action(username, 'Unknown', 'Login Failed', 'Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    username = session.get('username', 'Unknown')
    role = session.get('role', 'Unknown')
    session.clear()
    flash('Logged out successfully', 'success')
    log_action(username, role, 'Logout', 'User logged out')
    return redirect(url_for('login'))

@app.route('/', defaults={'page': 'dashboard'})
@app.route('/<page>')
@role_required('Administrator', 'Approver', 'Contributor')
def index(page):
    if page not in ['dashboard', 'pending', 'devices', 'settings', 'audit_log']:
        log_action(session.get('username'), session.get('role'), 'Invalid Page Access', f"Attempted access to {page}")
        abort(404)
    if page in ['settings', 'audit_log'] and session.get('role') != 'Administrator':
        log_action(session.get('username'), session.get('role'), 'Unauthorized Access', f"Attempted access to {page}")
        abort(403)
    
    with sqlite3.connect('devices.db') as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM pending_devices')
        pending_devices = [
            {"mac": row[0], "seen": row[1], "switch_ip": row[2], "port": row[3]}
            for row in c.fetchall()
        ]
        c.execute('SELECT mac, description, group_name, assigned_user FROM mab_devices')
        mab_devices = [
            {"mac": row[0], "desc": row[1], "group": row[2], "assigned_user": row[3]}
            for row in c.fetchall()
        ]
        if page == 'audit_log':
            c.execute('SELECT * FROM audit_log ORDER BY timestamp DESC')
            logs = [
                {"id": row[0], "timestamp": row[1], "username": row[2], "role": row[3], "action": row[4], "details": row[5]}
                for row in c.fetchall()
            ]
        else:
            logs = None

        # Data for dashboard charts
        if page == 'dashboard':
            group_counts = {}
            for device in mab_devices:
                group = device['group']
                group_counts[group] = group_counts.get(group, 0) + 1

            c.execute("SELECT assigned_user, COUNT(*) FROM mab_devices WHERE assigned_user IS NOT NULL GROUP BY assigned_user")
            user_device_counts = c.fetchall()

            chart_data = {
                'pending_count': len(pending_devices),
                'authorized_count': len(mab_devices),
                'group_labels': list(group_counts.keys()),
                'group_counts': list(group_counts.values()),
                'user_labels': [item[0] for item in user_device_counts],
                'user_counts': [item[1] for item in user_device_counts]
            }
        else:
            chart_data = None
    
    enriched_devices = []
    for dev in pending_devices:
        info = get_snmp_sysinfo(dev["switch_ip"])
        enriched_devices.append({
            **dev,
            "switch": info["name"],
            "location": info["location"]
        })

    authorize_form = AuthorizeDeviceForm()
    settings_form = SettingsForm()
    log_action(session.get('username'), session.get('role'), 'Page Access', f"Viewed {page} page")
    return render_template('portal.html', page=page, devices=enriched_devices, mab_devices=mab_devices, 
                           authorize_form=authorize_form, settings_form=settings_form, logs=logs, chart_data=chart_data)

@app.route('/add-mab-device', methods=['GET', 'POST'])
@role_required('Administrator', 'Contributor')
def add_device():
    form = AddDeviceForm()
    if form.validate_on_submit():
        mac = bleach.clean(form.mac.data)
        description = bleach.clean(form.description.data)
        with sqlite3.connect('devices.db') as conn:
            c = conn.cursor()
            c.execute('INSERT INTO pending_devices (mac, seen, switch_ip, port) VALUES (?, ?, ?, ?)',
                      (mac, datetime.now().strftime("%Y-%m-%d %H:%M"), '10.45.18.1', 'Gi1/0/10'))
            conn.commit()
        flash('Device added successfully', 'success')
        log_action(session.get('username'), session.get('role'), 'Add Device', f"Added device {mac}")
        return redirect(url_for('index', page='pending'))
    return render_template('add.html', form=form)

@app.route('/authorize-device', methods=['POST'])
@role_required('Administrator', 'Approver')
def authorize_device():
    form = AuthorizeDeviceForm()
    if form.validate_on_submit():
        mac = bleach.clean(form.mac.data)
        with sqlite3.connect('devices.db') as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM pending_devices WHERE mac = ?', (mac,))
            device = c.fetchone()
            if device:
                c.execute('INSERT INTO mab_devices (mac, description, group_name) VALUES (?, ?, ?)',
                          (mac, 'Authorized Device', form.group.data))
                c.execute('DELETE FROM pending_devices WHERE mac = ?', (mac,))
                conn.commit()
                response = cisco_ise_api_authorize(mac, form.group.data)
                if response['status'] == 'success':
                    flash(response['message'], 'success')
                    log_action(session.get('username'), session.get('role'), 'Authorize Device', f"Authorized {mac} in group {form.group.data}")
                else:
                    flash(response['message'], 'error')
                    log_action(session.get('username'), session.get('role'), 'Authorize Device Failed', f"Failed to authorize {mac}: {response['message']}")
            else:
                flash('Device not found', 'error')
                log_action(session.get('username'), session.get('role'), 'Authorize Device Failed', f"Device {mac} not found")
        return redirect(url_for('index', page='pending'))
    flash('Invalid form data', 'error')
    log_action(session.get('username'), session.get('role'), 'Authorize Device Failed', 'Invalid form data')
    return redirect(url_for('index', page='pending'))

@app.route('/reject-device', methods=['POST'])
@role_required('Administrator', 'Approver')
def reject_device():
    mac = bleach.clean(request.form.get('mac'))
    with sqlite3.connect('devices.db') as conn:
        c = conn.cursor()
        c.execute('DELETE FROM pending_devices WHERE mac = ?', (mac,))
        conn.commit()
    flash(f'Device {mac} has been rejected and removed.', 'success')
    log_action(session.get('username'), session.get('role'), 'Reject Device', f"Rejected and removed device {mac}")
    return redirect(url_for('index', page='pending'))

@app.route('/edit-device/<mac>', methods=['GET', 'POST'])
@role_required('Administrator')
def edit_device(mac):
    mac = bleach.clean(mac)
    form = EditDeviceForm()
    with sqlite3.connect('devices.db') as conn:
        c = conn.cursor()
        c.execute('SELECT username FROM users')
        users = [user[0] for user in c.fetchall()]
        form.assigned_user.choices = [("", "-- Select User --")] + [(user, user) for user in users]

        c.execute('SELECT * FROM mab_devices WHERE mac = ?', (mac,))
        device = c.fetchone()
        if not device:
            log_action(session.get('username'), session.get('role'), 'Edit Device Failed', f"Device {mac} not found")
            abort(404)

        if form.validate_on_submit():
            description = bleach.clean(form.description.data)
            c.execute('UPDATE mab_devices SET description = ?, group_name = ?, assigned_user = ? WHERE mac = ?',
                      (description, form.group.data, form.assigned_user.data, mac))
            conn.commit()
            flash('Device updated successfully', 'success')
            log_action(session.get('username'), session.get('role'), 'Edit Device', f"Updated device {mac}")
            return redirect(url_for('index', page='devices'))

        if request.method == 'GET':
            form.mac.data = device[0]
            form.description.data = device[1]
            form.group.data = device[2]
            form.assigned_user.data = device[3]

    return render_template('edit.html', form=form)

@app.route('/delete-device/<mac>', methods=['POST'])
@role_required('Administrator')
def delete_device(mac):
    mac = bleach.clean(mac)
    with sqlite3.connect('devices.db') as conn:
        c = conn.cursor()
        c.execute('DELETE FROM mab_devices WHERE mac = ?', (mac,))
        conn.commit()
    flash('Device deleted successfully', 'success')
    log_action(session.get('username'), session.get('role'), 'Delete Device', f"Deleted device {mac}")
    return redirect(url_for('index', page='devices'))

@app.route('/settings', methods=['GET', 'POST'])
@role_required('Administrator')
def settings():
    form = SettingsForm()
    with sqlite3.connect('devices.db') as conn:
        c = conn.cursor()
        c.execute('SELECT key, value FROM settings WHERE key IN (?, ?, ?)',
                  ('snmp_community', 'ise_api_url', 'ise_username'))
        settings = {row[0]: row[1] for row in c.fetchall()}
        if request.method == 'GET':
            form.snmp_community.data = settings.get('snmp_community', 'public')
            form.ise_api_url.data = settings.get('ise_api_url', 'https://ise.example.com')
            form.ise_username.data = settings.get('ise_username', 'ise_user')
        if form.validate_on_submit():
            c.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)',
                      ('snmp_community', bleach.clean(form.snmp_community.data)))
            c.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)',
                      ('ise_api_url', bleach.clean(form.ise_api_url.data)))
            c.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)',
                      ('ise_username', bleach.clean(form.ise_username.data)))
            c.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)',
                      ('ise_password', bcrypt.generate_password_hash(form.ise_password.data).decode('utf-8')))
            conn.commit()
            flash('Settings updated successfully', 'success')
            log_action(session.get('username'), session.get('role'), 'Update Settings', 'Updated SNMP and ISE settings')
            return redirect(url_for('index', page='settings'))
    return render_template('settings.html', form=form)

@app.route('/manage-users', methods=['GET', 'POST'])
@role_required('Administrator')
def manage_users():
    form = UserForm()
    with sqlite3.connect('devices.db') as conn:
        c = conn.cursor()
        if form.validate_on_submit():
            username = bleach.clean(form.username.data)
            c.execute('SELECT username FROM users WHERE username = ?', (username,))
            if c.fetchone():
                flash('Username already exists', 'error')
                log_action(session.get('username'), session.get('role'), 'Add User Failed', f"Username {username} already exists")
            else:
                password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
                c.execute('INSERT INTO users (username, password, role, totp_secret) VALUES (?, ?, ?, ?)',
                          (username, password, form.role.data, ''))
                conn.commit()
                flash(f'User {username} added successfully', 'success')
                log_action(session.get('username'), session.get('role'), 'Add User', f"Added user {username} with role {form.role.data}")
            return redirect(url_for('manage_users'))
        c.execute('SELECT username, role, totp_secret FROM users')
        users = [(row[0], row[1], bool(row[2])) for row in c.fetchall()]
    return render_template('manage_users.html', form=form, users=users)

@app.route('/disable-2fa/<username>', methods=['POST'])
@role_required('Administrator')
def disable_2fa(username):
    username = bleach.clean(username)
    if username == session.get('username'):
        flash('Cannot disable 2FA for your own account', 'error')
        log_action(session.get('username'), session.get('role'), 'Disable 2FA Failed', 'Attempted to disable own 2FA')
        return redirect(url_for('manage_users'))
    with sqlite3.connect('devices.db') as conn:
        c = conn.cursor()
        c.execute('SELECT username FROM users WHERE username = ?', (username,))
        if not c.fetchone():
            flash(f'User {username} not found', 'error')
            log_action(session.get('username'), session.get('role'), 'Disable 2FA Failed', f"User {username} not found")
            return redirect(url_for('manage_users'))
        c.execute('UPDATE users SET totp_secret = ? WHERE username = ?', ('', username))
        conn.commit()
    flash(f'2FA disabled for user {username}', 'success')
    log_action(session.get('username'), session.get('role'), 'Disable 2FA', f"Disabled 2FA for user {username}")
    return redirect(url_for('manage_users'))

@app.route('/edit-user/<username>', methods=['GET', 'POST'])
@role_required('Administrator')
def edit_user(username):
    username = bleach.clean(username)
    form = EditUserForm()
    with sqlite3.connect('devices.db') as conn:
        c = conn.cursor()
        c.execute('SELECT username, role FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        if not user:
            abort(404)

        if form.validate_on_submit():
            c.execute('UPDATE users SET role = ? WHERE username = ?', (form.role.data, username))
            conn.commit()
            flash(f'User {username} updated successfully', 'success')
            log_action(session.get('username'), session.get('role'), 'Edit User', f"Updated user {username} with role {form.role.data}")
            return redirect(url_for('manage_users'))

        if request.method == 'GET':
            form.role.data = user[1]

    return render_template('edit_user.html', form=form, user={'username': user[0]})

@app.route('/delete-user/<username>', methods=['POST'])
@role_required('Administrator')
def delete_user(username):
    username = bleach.clean(username)
    if username == session.get('username'):
        flash('Cannot delete your own account', 'error')
        log_action(session.get('username'), session.get('role'), 'Delete User Failed', 'Attempted to delete own account')
        return redirect(url_for('manage_users'))
    with sqlite3.connect('devices.db') as conn:
        c = conn.cursor()
        c.execute('DELETE FROM users WHERE username = ?', (username,))
        conn.commit()
    flash(f'User {username} deleted successfully', 'success')
    log_action(session.get('username'), session.get('role'), 'Delete User', f"Deleted user {username}")
    return redirect(url_for('manage_users'))

@app.route('/export-devices')
@role_required('Administrator')
def export_devices():
    with sqlite3.connect('devices.db') as conn:
        c = conn.cursor()
        c.execute('SELECT mac, description, group_name FROM mab_devices')
        devices = c.fetchall()

    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['mac', 'description', 'group_name'])
    cw.writerows(devices)

    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=mab_devices.csv"
    output.headers["Content-type"] = "text/csv"
    log_action(session.get('username'), session.get('role'), 'Export Devices', 'Exported MAB devices to CSV')
    return output

@app.route('/import-devices', methods=['POST'])
@role_required('Administrator')
def import_devices():
    if 'file' not in request.files:
        flash('No file part. Please select a file to upload.', 'error')
        return redirect(url_for('index', page='devices'))
    file = request.files['file']
    if file.filename == '':
        flash('No selected file. Please choose a file to import.', 'error')
        return redirect(url_for('index', page='devices'))
    if not file.filename.endswith('.csv'):
        flash('Invalid file type. Only CSV files are allowed.', 'error')
        return redirect(url_for('index', page='devices'))

    try:
        stream = StringIO(file.stream.read().decode("UTF8"), newline=None)
        csv_input = csv.reader(stream)
        header = next(csv_input)
        if header != ['mac', 'description', 'group_name', 'assigned_user']:
            flash('CSV file has incorrect headers. Expected: mac, description, group_name, assigned_user', 'error')
            return redirect(url_for('index', page='devices'))

        with sqlite3.connect('devices.db') as conn:
            c = conn.cursor()
            imported_count = 0
            for row in csv_input:
                mac, description, group_name, assigned_user = row
                mac = bleach.clean(mac).strip()
                description = bleach.clean(description).strip()
                group_name = bleach.clean(group_name).strip()
                assigned_user = bleach.clean(assigned_user).strip() or None

                if re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac):
                    c.execute('INSERT OR REPLACE INTO mab_devices (mac, description, group_name, assigned_user) VALUES (?, ?, ?, ?)',
                              (mac, description, group_name, assigned_user))
                    imported_count += 1
            conn.commit()
        flash(f'Successfully imported {imported_count} devices.', 'success')
        log_action(session.get('username'), session.get('role'), 'Import Devices', f"Imported {imported_count} devices from CSV")
    except Exception as e:
        flash(f'An error occurred during import: {e}', 'error')
        log_action(session.get('username'), session.get('role'), 'Import Devices Failed', f"Error: {e}")

    return redirect(url_for('index', page='devices'))

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=3000, debug=True)
