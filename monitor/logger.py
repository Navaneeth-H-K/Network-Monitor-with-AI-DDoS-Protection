import sqlite3
from config import DATABASE_PATH


def log_traffic(features, status="NORMAL"):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO traffic (
            src_ip,
            syn_count,
            ack_count,
            packet_rate,
            syn_ack_rate,
            avg_frame_len,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        features["src_ip"],
        features["syn_count"],
        features["ack_count"],
        features["packet_rate"],
        features["syn_ack_ratio"], 
        features["avg_frame_len"],
        status
    ))

    conn.commit()
    conn.close()
