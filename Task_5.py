from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        proto = ip_layer.proto

        # Get TCP/UDP payload if possible
        if TCP in packet:
            payload = bytes(packet[TCP].payload)
            protocol = "TCP"
        elif UDP in packet:
            payload = bytes(packet[UDP].payload)
            protocol = "UDP"
        else:
            payload = b''
            protocol = proto

        print(f"Source: {src}, Destination: {dst}, Protocol: {protocol}, Payload: {payload[:30]}")

def main():
    print("=== Network Packet Sniffer (Educational Use) ===")
    print("Ctrl+C to stop.")
    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    main()
