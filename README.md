# CodeAlpha-Basic-Network-Sniffer-
from scapy.all import sniff, IP, TCP, UDP, ICMP

# Function to process each captured packet
def packet_callback(packet):
    
    # Check if packet contains IP layer
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        
        print("\n--- Packet Captured ---")
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        
        # Check protocol type
        if packet.haslayer(TCP):
            print("Protocol: TCP")
        
        elif packet.haslayer(UDP):
            print("Protocol: UDP")
        
        elif packet.haslayer(ICMP):
            print("Protocol: ICMP")
        
        else:
            print("Protocol: Other")
        
        # Display payload if present
        if packet.payload:
            print("Payload:", bytes(packet.payload))

# Start sniffing packets
print("Starting Packet Sniffer...")
sniff(prn=packet_callback, count=10)





