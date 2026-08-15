from flask import (
    Flask,
    render_template,
    jsonify,
    request,
    redirect,
    url_for,
    session,
)
import json
import os

app = Flask(__name__)

# Secret key for login session
app.secret_key = "smart_packet_analyzer_v5"

DATA_FILE = "data/packets.json"

# -----------------------------
# Login Credentials
# -----------------------------
USERNAME = "admin"
PASSWORD = "admin123"


# -----------------------------
# Default Dashboard Data
# -----------------------------
def default_data():
    return {
        "dashboard": {
            "packets": 0,
            "protocols": 0,
            "alerts": 0,
            "status": "Waiting..."
        },
        "security": {
            "score": 100,
            "health": "Excellent",
            "active_hosts": 0,
            "avg_packet": 0,
            "top_host": "-"
        },
        "protocols": {
            "TCP": 0,
            "UDP": 0,
            "HTTP": 0,
            "HTTPS": 0,
            "DNS": 0,
            "ICMP": 0,
            "OTHER": 0
        },
        "packets": [],
        "insights": []
    }


# -----------------------------
# Load JSON Data
# -----------------------------
def load_data():

    if not os.path.exists(DATA_FILE):
        return default_data()

    try:
        with open(DATA_FILE, "r") as f:
            return json.load(f)

    except Exception as e:
        print("Error:", e)
        return default_data()


# =====================================================
# LOGIN PAGE
# =====================================================

@app.route("/")
def home():

    if session.get("logged_in"):
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():

    if session.get("logged_in"):
        return redirect(url_for("dashboard"))

    error = ""

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        if username == USERNAME and password == PASSWORD:

            session["logged_in"] = True
            session["username"] = username

            return redirect(url_for("dashboard"))

        else:

            error = "Invalid Username or Password"

    return render_template("login.html", error=error)


# =====================================================
# DASHBOARD
# =====================================================

@app.route("/dashboard")
def dashboard():

    if not session.get("logged_in"):
        return redirect(url_for("login"))

    return render_template(
        "index.html",
        username=session.get("username")
    )


# =====================================================
# API
# =====================================================

@app.route("/data")
def data():

    if not session.get("logged_in"):
        return jsonify({"error": "Unauthorized"}), 401

    return jsonify(load_data())


# =====================================================
# LOGOUT
# =====================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# =====================================================
# RUN
# =====================================================

if __name__ == "__main__":
    app.run(debug=True)