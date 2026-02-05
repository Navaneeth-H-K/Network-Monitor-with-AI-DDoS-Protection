import time


class FeatureEngine:

    def __init__(self, window_size):
        self.window_size = window_size
        self.flow_stats = {}

    def update_packet(self, packet):
        src_ip = packet["src_ip"]
        now = time.time()

        if src_ip not in self.flow_stats:
            self.flow_stats[src_ip] = {
                "syn_count": 0,
                "ack_count": 0,
                "total_packets": 0,
                "total_bytes": 0,
                "start_time": now
            }

        stats = self.flow_stats[src_ip]

        stats["total_packets"] += 1
        stats["total_bytes"] += packet["size"]

        if packet["syn"]:
            stats["syn_count"] += 1

        if packet["ack"]:
            stats["ack_count"] += 1

        duration = now - stats["start_time"]

        if duration >= self.window_size:
            return self.compute_features(src_ip)

        return None

    def compute_features(self, src_ip):
        stats = self.flow_stats[src_ip]
        now = time.time()
        duration = now - stats["start_time"]

        # Prevent divide-by-zero or extremely small window
        if duration <= 0:
            duration = 1

        syn_count = stats["syn_count"]
        ack_count = stats["ack_count"]
        total_packets = stats["total_packets"]
        total_bytes = stats["total_bytes"]

        # Safe calculations
        packet_rate = total_packets / duration if total_packets > 0 else 0
        syn_ack_ratio = syn_count / (ack_count + 1)  # +1 avoids zero division
        avg_frame_len = total_bytes / total_packets if total_packets > 0 else 0

        features = {
            "src_ip": src_ip,
            "syn_count": syn_count,
            "ack_count": ack_count,
            "packet_rate": packet_rate,
            "syn_ack_ratio": syn_ack_ratio,
            "avg_frame_len": avg_frame_len
        }

        # Reset window
        self.flow_stats[src_ip] = {
            "syn_count": 0,
            "ack_count": 0,
            "total_packets": 0,
            "total_bytes": 0,
            "start_time": now
        }

        return features
