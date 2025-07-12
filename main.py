from flask import Flask, render_template, request, redirect, url_for
from datetime import datetime

app = Flask(__name__)

# Static mock data for UI test
pending_devices = [
    {
        "mac": "AA:BB:CC:DD:EE:FF",
        "seen": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "switch": "SW1-HQ",
        "location": "DK-MOR01-1stFloor",
        "port": "Gi1/0/10"
    },
    {
        "mac": "11:22:33:44:55:66",
        "seen": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "switch": "SW2-BRANCH",
        "location": "DK-MOR02-MeetingRoom",
        "port": "Gi1/0/11"
    }
]

@app.route("/")
def index():
    return render_template("portal.html", devices=pending_devices)

@app.route("/add-mab-device", methods=["POST"])
def add_device():
    return redirect(url_for("index"))

@app.route("/authorize-device", methods=["POST"])
def authorize_device():
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000)
