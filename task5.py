from scapy.arch.windows import get_windows_if_list
from scapy.all import IP, sniff

MTU = 1500

def packet_callback(packet):
    if IP in packet:
        print(f"Source IP: {packet[IP].src}, Destination IP: {packet[IP].dst}")

def list_interfaces():
    interfaces = get_windows_if_list()
    print("Available Interfaces:")
    for i, interface in enumerate(interfaces):
        print(f"{i+1}. {interface['name']}")
    return interfaces

def main():
    interfaces = list_interfaces()

    if not interfaces:
        print("No interfaces found. Exiting.")
        return

    index = int(input("Enter the index of the interface to sniff: ")) - 1
    selected_interface = interfaces[index]['name']

    try:
        print(f"Sniffing on interface {selected_interface}...")

        sniff(iface=selected_interface, prn=packet_callback, store=0)

    except KeyboardInterrupt:
        print("\nSniffing stopped.")

if __name__ == "__main__":
    main()