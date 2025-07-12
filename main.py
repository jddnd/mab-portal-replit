from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Regexp, Length
from datetime import datetime
import sqlite3
import re
import os
from pysnmp.hlapi import *
from functools import wraps
from flask_bcrypt import Bcrypt
import bleach
import requests

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'supersecurekey123456')  # Use env var in production
app.config['SESSION_COOKIE_SECURE'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes session timeout
bcrypt = Bcrypt(app)

# Initialize SQLite database
def init_db():
    with sqlite3.connect('devices.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS pending_devices
                     (mac TEXT PRIMARY KEY, seen TEXT, switch_ip TEXT, port TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS mab_devices
                     (mac TEXT PRIMARY KEY, description TEXT, group_name TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (username TEXT PRIMARY KEY, password TEXT, role TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS settings
                     (key TEXT PRIMARY KEY, value TEXT)''')
        # Insert initial data for testing
        c.execute('INSERT OR IGNORE INTO pending_devices (mac, seen, switch_ip, port) VALUES (?, ?, ?, ?)',
                  ('AA:BB:CC:DD:EE:FF', '2025-07-12 09:32', '10.45.18.1', 'Gi1/0/10'))
        c.execute('INSERT OR IGNORE INTO pending_devices (mac, seen, switch_ip, port) VALUES (?, ?, ?, ?)',
                  ('11:22:33:44:55:66', '2025-07-12 09:45', '10.45.22.1', 'Gi1/0/11'))
        # Insert default users
        admin_password = bcrypt.generate_password_hash('StrongPassword123').decode('utf-8')
        approver_password = bcrypt.generate_password_hash('ApproverPass123').decode('utf-8')
        contributor_password = bcrypt.generate_password_hash('ContributorPass123').decode('utf-8')
        c.execute('INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)',
                  ('admin', admin_password, 'Administrator'))
        c.execute('INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)',
                  ('approver', approver_password, 'Approver'))
        c.execute('INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)',
                  ('contributor', contributor_password, 'Contributor'))
        # Insert default settings
        c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', ('snmp_community', 'public'))
        c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', ('ise_api_url', 'https://ise.example.com'))
        c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', ('ise_username', 'ise_user'))
        c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', ('ise_password', 'ise_pass'))
        conn.commit()

# Mock Cisco ISE API (replace with real API call in production)
def cisco_ise_api_authorize(mac, group):
    with sqlite3.connect('devices.db') as conn:
        c = conn.cursor()
        c.execute('SELECT value FROM settings WHERE key IN (?, ?, ?)',
                  ('ise_api_url', 'ise_username', 'ise_password'))
        settings = c.fetchall()
        ise_url, ise_username, ise_password = [s[0] for s in settings]
    
    try:
        # Mock API call (replace with actual Cisco ISE API call)
        # Example: requests.post(f"{ise_url}/api/v1/mab", json={"mac": mac, "group": group}, auth=(ise_username, ise_password))
        response = {"status": "success", "message": f"Device {mac} authorized in group {group}"}
        return response
    except Exception as e:
        return {"status": "error", "message": str(e)}

# SNMP function to fetch switch info
def get_snmp_sysinfo(ip):
    with sqlite3.connect('devices.db') as conn:
        c = conn.cursor()
        c.execute('SELECT value FROM settings WHERE key = ?', ('snmp_community',))
        community = c.fetchone()[0] or 'public'

    sys_name_oid = '1.3.6.1.2.1.1.5.0'
    sys_location_oid = '1.3.6.1.2.1.1.6.0'
    result = {'name': 'Unknown', 'location': 'Unknown'}

    for oid, key in [(sys_name_oid, 'name'), (sys_location_oid, 'location')]:
        try:
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=1),
                UdpTransportTarget((ip, 161), timeout=3, retries=2),
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            )
            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
            if not errorIndication and not errorStatus:
                for varBind in varBinds:
                    result[key] = str(varBind[1])
        except Exception as e:
            print(f"SNMP error for {ip}: {e}")
    return result

# Forms with CSRF protection
class AddDeviceForm(FlaskForm):
    mac = StringField('MAC Address', validators=[
        DataRequired(), 
        Regexp(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', message="Invalid MAC address")
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
    submit = SubmitField('Save Changes')

class SettingsForm(FlaskForm):
    snmp_community = StringField('SNMP Community String', validators=[DataRequired()])
    ise_api_url = StringField('Cisco ISE API URL', validators=[DataRequired()])
    ise_username = StringField('Cisco ISE Username', validators=[DataRequired()])
    ise_password = PasswordField('Cisco ISE Password', validators=[DataRequired()])
    submit = SubmitField('Save Settings')

# Role-based access control decorator
def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('logged_in'):
                return redirect(url_for('login'))
            user_role = session.get('role')
            if user_role not in roles:
                flash('Unauthorized access', 'error')
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = bleach.clean(request.form.get('username'))
        password = request.form.get('password')
        with sqlite3.connect('devices.db') as conn:
            c = conn.cursor()
            c.execute('SELECT password, role FROM users WHERE username = ?', (username,))
            user = c.fetchone()
            if user and bcrypt.check_password_hash(user[0], password):
                session['logged_in'] = True
                session['username'] = username
                session['role'] = user[1]
                session.permanent = True
                return redirect(url_for('index', page='dashboard'))
            flash('Invalid credentials', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/', defaults={'page': 'dashboard'})
@app.route('/<page>')
@role_required('Administrator', 'Approver', 'Contributor')
def index(page):
    if page not in ['dashboard', 'pending', 'devices', 'settings']:
        abort(404)
    if page == 'settings' and session.get('role') != 'Administrator':
        abort(403)
    
    with sqlite3.connect('devices.db') as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM pending_devices')
        pending_devices = [
            {"mac": row[0], "seen": row[1], "switch_ip": row[2], "port": row[3]}
            for row in c.fetchall()
        ]
        c.execute('SELECT * FROM mab_devices')
        mab_devices = [
            {"mac": row[0], "desc": row[1], "group": row[2]}
            for row in c.fetchall()
        ]
    
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
    return render_template('portal.html', page=page, devices=enriched_devices, mab_devices=mab_devices, 
                           authorize_form=authorize_form, settings_form=settings_form)

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
                      (mac, datetime.now().strftime("%Y-%m-%d %H:%M"), '10.45.18.1', 'Gi1/0/10'))  # Mock switch_ip/port
            conn.commit()
        flash('Device added successfully', 'success')
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
                # Call Cisco ISE API
                response = cisco_ise_api_authorize(mac, form.group.data)
                if response['status'] == 'success':
                    flash(response['message'], 'success')
                else:
                    flash(response['message'], 'error')
            else:
                flash('Device not found', 'error')
        return redirect(url_for('index', page='devices'))
    flash('Invalid form data', 'error')
    return redirect(url_for('index', page='pending'))

@app.route('/edit-device/<mac>', methods=['GET', 'POST'])
@role_required('Administrator')
def edit_device(mac):
    mac = bleach.clean(mac)
    form = EditDeviceForm()
    with sqlite3.connect('devices.db') as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM mab_devices WHERE mac = ?', (mac,))
        device = c.fetchone()
        if not device:
            abort(404)
        if request.method == 'GET':
            form.mac.data = device[0]
            form.description.data = device[1]
            form.group.data = device[2]
        if form.validate_on_submit():
            description = bleach.clean(form.description.data)
            c.execute('UPDATE mab_devices SET description = ?, group_name = ? WHERE mac = ?',
                      (description, form.group.data, mac))
            conn.commit()
            flash('Device updated successfully', 'success')
            return redirect(url_for('index', page='devices'))
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
            return redirect(url_for('index', page='settings'))
    return render_template('settings.html', form=form)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=3000, debug=True)
