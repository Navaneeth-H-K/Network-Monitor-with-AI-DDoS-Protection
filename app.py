from flask import Flask, render_template, redirect, url_for
import sqlite3
from multiprocessing import Process

from config import DATABASE_PATH
from monitor.packet_sniffer import start_sniffer
from monitor.firewall import unblock_ip


app = Flask(__name__)


# ------------------------------
# DATABASE CONNECTION
# ------------------------------
def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
def dashboard():
    conn = get_db_connection()

    # Get last 50 entries for stats
    traffic_50 = conn.execute("""
        SELECT * FROM traffic
        ORDER BY id DESC
        LIMIT 50
    """).fetchall()

    # Get last 10 entries for display
    traffic_10 = conn.execute("""
        SELECT * FROM traffic
        ORDER BY id DESC
        LIMIT 10
    """).fetchall()

    blocked_ips = conn.execute("""
        SELECT * FROM blocked_ips
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        traffic_50=traffic_50,
        traffic_10=traffic_10,
        blocked_ips=blocked_ips
    )



# ------------------------------
# UNBLOCK ROUTE (WITH COOLDOWN)
# ------------------------------
@app.route("/unblock/<ip>")
def unblock(ip):

    # Remove from database
    conn = get_db_connection()
    conn.execute("DELETE FROM blocked_ips WHERE ip=?", (ip,))
    conn.commit()
    conn.close()

    # Remove firewall rule + activate cooldown
    unblock_ip(ip)

    print(f"🔓 Manual unblock triggered for {ip}")

    return redirect(url_for("dashboard"))


# ------------------------------
# MAIN ENTRY
# ------------------------------
if __name__ == "__main__":

    print("🚀 Starting sniffer process...")

    sniffer_process = Process(target=start_sniffer)
    sniffer_process.daemon = True
    sniffer_process.start()

    print("🌐 Starting Flask server...")

    app.run(host="0.0.0.0", port=8000)
