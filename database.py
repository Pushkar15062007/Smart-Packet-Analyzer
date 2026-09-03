import sqlite3
import os

DATABASE_FILE = "data/packets.db"


def get_connection():
    os.makedirs("data", exist_ok=True)

    connection = sqlite3.connect(
        DATABASE_FILE,
        check_same_thread=False
    )

    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time TEXT,
            src TEXT,
            dst TEXT,
            protocol TEXT,
            length INTEGER,
            risk TEXT,
            port TEXT,
            src_port TEXT,
            src_mac TEXT,
            dst_mac TEXT,
            eth_type TEXT,
            ttl TEXT,
            flags TEXT,
            window TEXT,
            hex TEXT,
            http_method TEXT,
            http_host TEXT,
            http_uri TEXT,
            user_agent TEXT,
            dns_query TEXT,
            dns_response TEXT,
            dns_type TEXT,
            tls_version TEXT,
            sni TEXT,
            cipher TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time TEXT,
            risk TEXT,
            description TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS network_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time TEXT,
            total_packets INTEGER,
            active_hosts INTEGER,
            avg_packet REAL,
            bandwidth REAL
        )
    """)

    connection.commit()
    connection.close()

    print("SQLite database initialized successfully.")


if __name__ == "__main__":
    initialize_database()