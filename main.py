from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from datetime import datetime
import re

app = Flask(__name__)
app.secret_key = 'supersecurekey123456'  # Change in production

USERNAME = 'admin'
PASSWORD = 'StrongPassword123'

# In-memory store for now (use DB or file in real system)
pending_devices = [
    {"mac": "AA:BB:CC:DD:EE:FF", "seen": datetime.now().strftime("%Y-%m-%d %H:%M"), "switch": "SW1-HQ", "location": "DK-MOR01", "port": "Gi1/0/1"}
]

mab_devices = [
    {"mac": "11:22:33:44:55:66", "desc": "Printer HR DK-01", "group": "Printers"},
    {"mac": "22:33:44:55:66:77", "desc": "Meeting Room IoT", "group": "IoT_Meeting"}
]

def is_valid_mac(mac):
    return re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac)

@app.before_request
def require_login():
    if request.endpoint not in ['login', 'static'] and not session.get('logged_in'):
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form['username'] == USERNAME and request.form['password'] == PASSWORD:
            session['logged_in'] = True
            session['username'] = USERNAME
            return redirect(url_for('dashboard'))
        flash("Invalid credentials")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
def dashboard():
    return render_template('portal.html', page='dashboard', devices=pending_devices)

@app.route('/pending')
def pending():
    return render_template('portal.html', page='pending', devices=pending_devices)

@app.route('/devices')
def devices():
    return render_template('portal.html', page='devices', mab_devices=mab_devices)

@app.route('/settings')
def settings():
    if session.get('username') != 'admin':
        abort(403)
    return render_template('portal.html', page='settings', devices=[])

@app.route('/authorize-device', methods=['POST'])
def authorize_device():
    mac = request.form.get('mac')
    group = request.form.get('group')
    if not is_valid_mac(mac):
        abort(400)
    print(f"[AUTH] MAC {mac} → Group {group}")
    return redirect(url_for('pending'))

@app.route('/delete-device', methods=['POST'])
def delete_device():
    mac = request.form.get('mac')
    global mab_devices
    mab_devices = [d for d in mab_devices if d['mac'].lower() != mac.lower()]
    return redirect(url_for('devices'))

@app.route('/edit-device', methods=['GET', 'POST'])
def edit_device():
    mac = request.values.get('mac')
    device = next((d for d in mab_devices if d['mac'].lower() == mac.lower()), None)
    if request.method == 'POST':
        desc = request.form.get('desc')
        group = request.form.get('group')
        if device:
            device['desc'] = desc
            device['group'] = group
        return redirect(url_for('devices'))
    return render_template('edit.html', device=device)

@app.route('/add-device', methods=['GET', 'POST'])
def add_device():
    if request.method == 'POST':
        mac = request.form.get('mac')
        desc = request.form.get('desc')
        group = request.form.get('group')
        if not is_valid_mac(mac) or len(desc.strip()) < 3:
            flash("Invalid MAC or description")
            return redirect(url_for('add_device'))
        mab_devices.append({"mac": mac, "desc": desc, "group": group})
        return redirect(url_for('devices'))
    return render_template('add.html')

if __name__ == '__main__':
    app.run(debug=True)
