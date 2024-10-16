from scapy.all import get_if_list, sniff
import time

# To store if packets were captured on the current interface
packets_captured = False

# Callback function to handle each captured packet
def packet_callback(packet):
    global packets_captured
    packets_captured = True  # Set flag to True when a packet is captured
    print(packet.summary())  # Print packet summary or process it further

def capture_packets_on_interface(iface, capture_duration=10):
    global packets_captured
    packets_captured = False  # Reset flag before starting capture

    print(f"Attempting to capture packets on {iface} for {capture_duration} seconds...")
    try:
        sniff(iface=iface, prn=packet_callback, store=False, timeout=capture_duration)
        return packets_captured  # Return whether packets were captured or not
    except Exception as e:
        print(f"Failed to capture packets on {iface}. Error: {e}")
        return False

# List all available network interfaces
interfaces = get_if_list()
print("Available network interfaces:")
for iface in interfaces:
    print(iface)

# Loop through interfaces and try to capture packets
for iface in interfaces:
    if capture_packets_on_interface(iface):
        print(f"Packets captured successfully on {iface}. Staying on this interface.")
        break  # Stay on this interface and stop checking others
    else:
        print(f"No packets captured on {iface}. Trying the next interface...")
else:
    print("No packets were captured on any of the interfaces.")
