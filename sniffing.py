
from scapy.all import sniff

def analyze_packet(packet):
    """
    Callback function to process and analyze captured packets.
    """
    # Print the packet summary
    print(packet.summary())
    
    # Check if the packet contains IP layer and print details
    if packet.haslayer('IP'):
        ip_layer = packet['IP']
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")
        print("-" * 50)

def main():
    """
    Main function to capture network packets.
    """
    print("Starting network sniffer...")
    print("Press Ctrl+C to stop.")
    try:
        # Capture packets from all interfaces, store=False to process them live
        sniff(prn=analyze_packet, store=False)
    except KeyboardInterrupt:
        print("\nSniffing stopped.")

if __name__ == "__main__":
    main()
