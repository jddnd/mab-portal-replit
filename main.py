from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField
from wtforms.validators import DataRequired, Regexp, Length
from datetime import datetime
import sqlite3
import re
import os
from pysnmp.hlapi import *
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'supersecurekey123456')  # Use env var in production
app.config['SESSION_COOKIE_SECURE'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes session timeout

# Initialize SQLite database
def init_db():
    with sqlite3.connect('devices.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS pending_devices
                     (mac TEXT PRIMARY KEY, seen TEXT, switch_ip TEXT, port TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS mab_devices
                     (mac TEXT PRIMARY KEY, description TEXT, group_name TEXT)''')
        # Insert initial data for testing
        c.execute('INSERT OR IGNORE INTO pending_devices (mac, seen, switch_ip, port) VALUES (?, ?, ?, ?)',
                  ('AA:BB:CC:DD:EE:FF', '2025-07-12 09:32', '10.45.18.1', 'Gi1/0/10'))
        c.execute('INSERT OR IGNORE INTO pending_devices (mac, seen, switch_ip, port) VALUES (?, ?, ?, ?)',
                  ('11:22:33:44:55:66', '2025-07-12 09:45', '10.45.22.1', 'Gi1/0/11'))
        conn.commit()

# Mock Cisco ISE API
def cisco_ise_api_mock(mac, group):
    return {"status": "success", "message": f"Device {mac} authorized in group {group}"}

# SNMP function to fetch switch info
def get_snmp_sysinfo(ip, community='public'):
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

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == os.environ.get('ADMIN_USERNAME', 'admin') and password == os.environ.get('ADMIN_PASSWORD', 'StrongPassword123'):
            session['logged_in'] = True
            session['username'] = username
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
@login_required
def index(page):
    if page not in ['dashboard', 'pending', 'devices', 'settings']:
        abort(404)
    if page == 'settings' and session.get('username') != 'admin':
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

    return render_template('portal.html', page=page, devices=enriched_devices, mab_devices=mab_devices)

@app.route('/add-mab-device', methods=['GET', 'POST'])
@login_required
def add_device():
    form = AddDeviceForm()
    if form.validate_on_submit():
        with sqlite3.connect('devices.db') as conn:
            c = conn.cursor()
            c.execute('INSERT INTO pending_devices (mac, seen, switch_ip, port) VALUES (?, ?, ?, ?)',
                      (form.mac.data, datetime.now().strftime("%Y-%m-%d %H:%M"), '10.45.18.1', 'Gi1/0/10'))  # Mock switch_ip/port
            conn.commit()
        flash('Device added successfully', 'success')
        return redirect(url_for('index', page='pending'))
    return render_template('add.html', form=form)

@app.route('/authorize-device', methods=['POST'])
@login_required
def authorize_device():
    form = AuthorizeDeviceForm()
    if form.validate_on_submit():
        with sqlite3.connect('devices.db') as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM pending_devices WHERE mac = ?', (form.mac.data,))
            device = c.fetchone()
            if device:
                c.execute('INSERT INTO mab_devices (mac, description, group_name) VALUES (?, ?, ?)',
                          (form.mac.data, 'Authorized Device', form.group.data))
                c.execute('DELETE FROM pending_devices WHERE mac = ?', (form.mac.data,))
                conn.commit()
                # Simulate Cisco ISE API call
                cisco_ise_api_mock(form.mac.data, form.group.data)
                flash(f'Device {form.mac.data} authorized successfully', 'success')
            else:
                flash('Device not found', 'error')
        return redirect(url_for('index', page='devices'))
    flash('Invalid form data', 'error')
    return redirect(url_for('index', page='pending'))

@app.route('/edit-device/<mac>', methods=['GET', 'POST'])
@login_required
def edit_device(mac):
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
            c.execute('UPDATE mab_devices SET description = ?, group_name = ? WHERE mac = ?',
                      (form.description.data, form.group.data, mac))
            conn.commit()
            flash('Device updated successfully', 'success')
            return redirect(url_for('index', page='devices'))
    return render_template('edit.html', form=form)

@app.route('/delete-device/<mac>', methods=['POST'])
@login_required
def delete_device(mac):
    with sqlite3.connect('devices.db') as conn:
        c = conn.cursor()
        c.execute('DELETE FROM mab_devices WHERE mac = ?', (mac,))
        conn.commit()
    flash('Device deleted successfully', 'success')
    return redirect(url_for('index', page='devices'))

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=3000, debug=True)
