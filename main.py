from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from datetime import datetime
import re

app = Flask(__name__)
app.secret_key = 'supersecurekey123456'

USERNAME = 'admin'
PASSWORD = 'StrongPassword123'

pending_devices = [
    {
        "mac": "AA:BB:CC:DD:EE:FF",
        "seen": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "switch": "SW1-HQ",
        "location": "DK-MOR01-1stFloor",
        "port": "Gi1/0/10"
    }
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
            return redirect(url_for('index'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
def index():
    return render_template('portal.html', devices=pending_devices)

@app.route('/authorize-device', methods=['POST'])
def authorize_device():
    mac = request.form.get('mac')
    group = request.form.get('group')
    if not is_valid_mac(mac) or group not in ['Printers', 'IoT_Meeting', 'Mgmt_AP', 'Mgmt_SW']:
        abort(400)
    return redirect(url_for('index'))

@app.route('/add-mab-device', methods=['POST'])
def add_device():
    mac = request.form.get('mac')
    group = request.form.get('group')
    desc = request.form.get('desc')
    if not is_valid_mac(mac) or group not in ['Printers', 'IoT_Meeting', 'Mgmt_AP', 'Mgmt_SW'] or len(desc.strip()) < 3:
        abort(400)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000)
