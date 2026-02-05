import sqlite3
import subprocess
import time
from config import DATABASE_PATH

# Cooldown dictionary
cooldown_ips = {}
COOLDOWN_TIME = 30  # seconds


def is_ip_blocked(ip):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM blocked_ips WHERE ip=?", (ip,))
    result = cursor.fetchone()
    conn.close()
    return result is not None


def add_blocked_ip_to_db(ip):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT OR IGNORE INTO blocked_ips (ip) VALUES (?)", (ip,))
    conn.commit()
    conn.close()


def unblock_ip(ip):
    cooldown_ips[ip] = time.time()

    subprocess.run(
        ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
        check=False
    )


def block_ip(ip):

    if ip.startswith("127."):
        return

    # Check cooldown
    if ip in cooldown_ips:
        if time.time() - cooldown_ips[ip] < COOLDOWN_TIME:
            print(f"⏳ Cooldown active for {ip}, skipping block.")
            return
        else:
            del cooldown_ips[ip]

    if is_ip_blocked(ip):
        return

    print(f"🚨 BLOCKING IP: {ip}")

    subprocess.run(
        ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
        check=False
    )

    add_blocked_ip_to_db(ip)
