from flask import Flask, render_template, jsonify
import json
import os

app = Flask(__name__)

DATA_FILE = "data/packets.json"


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


def load_data():

    if not os.path.exists(DATA_FILE):
        return default_data()

    try:

        with open(DATA_FILE, "r") as f:
            return json.load(f)

    except Exception as e:

        print("Error:", e)

        return default_data()


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/data")
def data():
    return jsonify(load_data())


if __name__ == "__main__":
    app.run(debug=True)