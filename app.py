from flask import (
    Flask,
    render_template,
    jsonify,
    request,
    redirect,
    url_for,
    session,
)

from database import get_connection, initialize_database
from capture import start_capture


app = Flask(__name__)

# =====================================================
# SECRET KEY
# =====================================================

app.secret_key = "smart_packet_analyzer_v5"


# =====================================================
# DATABASE
# =====================================================

DATABASE_FILE = "data/packets.db"


# =====================================================
# LOGIN CREDENTIALS
# =====================================================

USERNAME = "admin"
PASSWORD = "admin123"


# =====================================================
# DEFAULT DASHBOARD DATA
# =====================================================

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

        "bandwidth": {
            "download": 0,
            "upload": 0,
            "total": 0
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


# =====================================================
# LOAD DATA FROM SQLITE
# =====================================================

def load_data():

    try:

        connection = get_connection()
        cursor = connection.cursor()

        # -------------------------------------------------
        # TOTAL PACKETS
        # -------------------------------------------------

        total_packets = cursor.execute(
            "SELECT COUNT(*) FROM packets"
        ).fetchone()[0]


        # -------------------------------------------------
        # LATEST 100 PACKETS
        # -------------------------------------------------

        rows = cursor.execute("""
            SELECT
                id,
                time,
                src,
                dst,
                protocol,
                length,
                risk,
                port,
                src_port,
                src_mac,
                dst_mac,
                eth_type,
                ttl,
                flags,
                window,
                hex,
                http_method,
                http_host,
                http_uri,
                user_agent,
                dns_query,
                dns_response,
                dns_type,
                tls_version,
                sni,
                cipher
            FROM packets
            ORDER BY id DESC
            LIMIT 100
        """).fetchall()


        packet_list = []

        for row in rows:

            packet_list.append(dict(row))


        # -------------------------------------------------
        # PROTOCOL COUNTS
        # -------------------------------------------------

        protocol_rows = cursor.execute("""
            SELECT protocol, COUNT(*) AS count
            FROM packets
            GROUP BY protocol
        """).fetchall()


        protocol_counts = {

            "TCP": 0,
            "UDP": 0,
            "HTTP": 0,
            "HTTPS": 0,
            "DNS": 0,
            "ICMP": 0,
            "OTHER": 0

        }


        for row in protocol_rows:

            protocol = row["protocol"]
            count = row["count"]

            if protocol in protocol_counts:

                protocol_counts[protocol] = count


        # -------------------------------------------------
        # ACTIVE HOSTS
        # -------------------------------------------------

        active_hosts = cursor.execute("""
            SELECT COUNT(DISTINCT src)
            FROM packets
            WHERE src != '-'
        """).fetchone()[0]


        # -------------------------------------------------
        # AVERAGE PACKET SIZE
        # -------------------------------------------------

        avg_packet = cursor.execute("""
            SELECT AVG(length)
            FROM packets
        """).fetchone()[0]


        if avg_packet is None:

            avg_packet = 0

        else:

            avg_packet = round(avg_packet, 2)


        # -------------------------------------------------
        # TOP HOST
        # -------------------------------------------------

        top_host_row = cursor.execute("""
            SELECT src, COUNT(*) AS count
            FROM packets
            WHERE src != '-'
            GROUP BY src
            ORDER BY count DESC
            LIMIT 1
        """).fetchone()


        if top_host_row:

            top_host = top_host_row["src"]

        else:

            top_host = "-"


        # -------------------------------------------------
        # SECURITY ALERTS
        # -------------------------------------------------

        alerts = cursor.execute("""
            SELECT COUNT(*)
            FROM packets
            WHERE risk IN ('HIGH', 'CRITICAL')
        """).fetchone()[0]


        # -------------------------------------------------
        # SECURITY SCORE
        # -------------------------------------------------

        security_score = max(
            0,
            100 - alerts
        )


        # -------------------------------------------------
        # NETWORK HEALTH
        # -------------------------------------------------

        network_health = "Healthy"


        if alerts > 20:

            network_health = "Critical"

        elif alerts > 10:

            network_health = "Warning"


        # -------------------------------------------------
        # ACTIVE PROTOCOL COUNT
        # -------------------------------------------------

        active_protocols = sum(

            1

            for value in protocol_counts.values()

            if value > 0

        )


        # -------------------------------------------------
        # TOP PROTOCOL
        # -------------------------------------------------

        if total_packets > 0:

            top_protocol = max(
                protocol_counts,
                key=protocol_counts.get
            )

        else:

            top_protocol = "-"


        # -------------------------------------------------
        # INSIGHTS
        # -------------------------------------------------

        insights = [

            {
                "title": "Traffic",
                "message":
                    f"Captured {total_packets} packets."
            },

            {
                "title": "Threats",
                "message":
                    f"{alerts} suspicious packets detected."
            },

            {
                "title": "Top Protocol",
                "message":
                    top_protocol
            }

        ]


        connection.close()


        # -------------------------------------------------
        # FINAL DASHBOARD DATA
        # -------------------------------------------------

        return {

            "dashboard": {

                "packets": total_packets,

                "protocols": active_protocols,

                "alerts": alerts,

                "status":
                    "Monitoring"
                    if total_packets > 0
                    else "Waiting..."

            },

            "security": {

                "score": security_score,

                "health": network_health,

                "active_hosts": active_hosts,

                "avg_packet": avg_packet,

                "top_host": top_host

            },

            "bandwidth": {

                "download": 0,

                "upload": 0,

                "total": 0

            },

            "protocols": protocol_counts,

            "packets": packet_list,

            "insights": insights

        }


    except Exception as e:

        print("SQLite Read Error:", e)

        return default_data()


# =====================================================
# INITIALIZE DATABASE
# =====================================================

initialize_database()


# =====================================================
# LOGIN PAGE
# =====================================================

@app.route("/")
def home():

    if session.get("logged_in"):

        return redirect(
            url_for("dashboard")
        )

    return redirect(
        url_for("login")
    )


@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if session.get("logged_in"):

        return redirect(
            url_for("dashboard")
        )


    error = ""


    if request.method == "POST":

        username = request.form.get("username")

        password = request.form.get("password")


        if (
            username == USERNAME
            and password == PASSWORD
        ):

            session["logged_in"] = True

            session["username"] = username

            return redirect(
                url_for("dashboard")
            )

        else:

            error = "Invalid Username or Password"


    return render_template(
        "login.html",
        error=error
    )


# =====================================================
# DASHBOARD
# =====================================================

@app.route("/dashboard")
def dashboard():

    if not session.get("logged_in"):

        return redirect(
            url_for("login")
        )


    return render_template(

        "index.html",

        username=session.get("username")

    )


# =====================================================
# DATA API
# =====================================================

@app.route("/data")
def data():

    if not session.get("logged_in"):

        return jsonify(
            {
                "error": "Unauthorized"
            }
        ), 401


    return jsonify(
        load_data()
    )


# =====================================================
# LOGOUT
# =====================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# =====================================================
# START APPLICATION
# =====================================================

if __name__ == "__main__":

    print("===================================")
    print(" SMART PACKET ANALYZER")
    print(" Starting Capture Engine...")
    print(" Starting Web Dashboard...")
    print("===================================")

    # Start Scapy + bandwidth monitoring
    start_capture()

    # Start Flask
    # debug=False prevents duplicate capture threads
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )