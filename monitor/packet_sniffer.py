from scapy.all import sniff, IP, TCP
from config import INTERFACE, PORT, WINDOW_SIZE
from monitor.feature_engine import FeatureEngine
from monitor.logger import log_traffic
from monitor.detection_engine import DetectionEngine
from monitor.firewall import block_ip


engine = FeatureEngine(WINDOW_SIZE)
detector = DetectionEngine()


def process_packet(packet):


    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return

    if packet[TCP].dport != PORT:
        return

    packet_data = {
        "src_ip": packet[IP].src,
        "size": len(packet),
        "syn": bool(packet[TCP].flags & 0x02),
        "ack": bool(packet[TCP].flags & 0x10)
    }

    features = engine.update_packet(packet_data)

    if features:
        status = detector.predict(features)

        print("\n==============================")
        print("🚦 WINDOW COMPLETE")
        print("IP:", features["src_ip"])
        print("🛡 STATUS:", status)
        print("==============================\n")

        log_traffic(features, status=status)

        if status == "ATTACK":
            block_ip(features["src_ip"])




def start_sniffer():
    sniff(
        iface=INTERFACE,
        filter=f"tcp port {PORT}",
        prn=process_packet,
        store=False
    )


