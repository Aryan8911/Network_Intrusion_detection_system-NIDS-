from scapy.all import sniff, IP, TCP, get_if_list
import pandas as pd
import joblib

# Load the models
model_external = joblib.load('nids_model_external.pkl')  # Ensure the model file is in the same directory
model_openstack = joblib.load('nids_model_openstack.pkl')  # Ensure the model file is in the same directory

def extract_features(packet):
    """Extract relevant features from the packet."""
    features = {
        'duration': 0,  # Placeholder, adjust as needed
        'proto': '',
        'packets': 1,  # For individual packets
        'bytes': len(bytes(packet)),  # Size of the packet
        'flows': 1,  # Placeholder for flows, can be adjusted as needed
        'tcp_urg': 1 if TCP in packet and packet[TCP].urg else 0,
        'tcp_ack': 1 if TCP in packet and packet[TCP].ack else 0,
        'tcp_psh': 1 if TCP in packet and packet[TCP].psh else 0,
        'tcp_rst': 1 if TCP in packet and packet[TCP].rst else 0,
        'tcp_syn': 1 if TCP in packet and packet[TCP].syn else 0,
        'tcp_fin': 1 if TCP in packet and packet[TCP].fin else 0,
        'tos': 0,  # Placeholder, adjust as needed
    }

    # Check if the packet is an IP packet
    if IP in packet:
        features['proto'] = packet[IP].proto  # Get protocol number

    # Return the features as a DataFrame for prediction
    return pd.DataFrame([features])

def packet_callback(packet):
    """Callback function to process each captured packet."""
    print(f"Captured Packet: {packet.summary()}")  # Debug print to see the captured packet
    features_df = extract_features(packet)

    # Make predictions using both models
    prediction_external = model_external.predict(features_df)
    print(f"Prediction (External Model): {prediction_external[0]}")

    prediction_openstack = model_openstack.predict(features_df)
    print(f"Prediction (OpenStack Model): {prediction_openstack[0]}")

# Get available interfaces
print("Available network interfaces:")
interfaces = get_if_list()  # List available interfaces
for iface in interfaces:
    print(iface)

# Run the packet sniffer
active_interface = None

while True:
    for iface in interfaces:
        try:
            print(f"Starting to capture packets on {iface}...")
            packets = sniff(iface=iface, prn=packet_callback, store=False, timeout=10)  # Adjust timeout as needed

            # If packets are captured, keep monitoring this interface
            if packets:
                active_interface = iface
                print(f"Packets captured on {iface}. Continuing to monitor this interface...")
                while True:
                    packets = sniff(iface=active_interface, prn=packet_callback, store=False, timeout=10)  # Adjust timeout as needed
            else:
                print(f"No packets captured on {iface}. Switching to the next interface...")
        except Exception as e:
            print(f"An error occurred on {iface}: {e}")

    # Optional: Break the loop after checking all interfaces
    # You can add a break condition based on your needs
    if active_interface is None:
        print("No active interface with packets. Waiting for packets on any interface...")
