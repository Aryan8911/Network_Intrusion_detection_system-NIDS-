from scapy.all import get_if_list

# Get and print the list of available network interfaces
interfaces = get_if_list()
print("Available network interfaces:")
for iface in interfaces:
    print(iface)
