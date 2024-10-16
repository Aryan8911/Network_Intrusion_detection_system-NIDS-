import pandas as pd
from scapy.all import sniff, get_if_list

# Callback function to process each packet
def packet_callback(packet):
    try:
        packet_info = {
            'Source IP': packet[0][1].src,
            'Destination IP': packet[0][1].dst,
            'Protocol': packet[0][1].proto,
            'Length': len(packet)
        }
        print(packet_info)
        df = pd.DataFrame([packet_info])
        df.to_csv('captured_packets.csv', mode='a', header=False, index=False)
    except IndexError:
        pass

def start_packet_capture(interface=None):
    if interface is None:
        interface = get_if_list()[0]  # Automatically choose the first interface
    sniff(iface=interface, prn=packet_callback, store=False)

if __name__ == "__main__":
    start_packet_capture()
