import os
import subprocess
from scapy.all import *
import datetime  # Add this line to import the datetime module


def capture_packets(interface, count=10):
    """
    Capture packets from the specified network.
    """
    pcap_file = "captured_packets.pcap"
    cmd = f"sudo tcpdump -i {interface} -c {count} -w {pcap_file}"
    try:
        subprocess.run(cmd, shell=True, check=True)
        print(f"Packets captured successfully! Saved to '{pcap_file}'")
        return pcap_file
    except subprocess.CalledProcessError:
        print("Oops! Something went wrong while capturing packets. Please try again.")


def analyze_packets(pcap_file, filter_option):
    """
    Analyze captured packets based on the user's choice.
    """
    analysis_result = {
        "ip_addresses": [],
        "protocols": [],
        "payload_data": []
    }
    
    try:
        packets = rdpcap(pcap_file)
        for packet in packets:
            if filter_option == "1":  # Analyze IP addresses
                if IP in packet:
                    analysis_result["ip_addresses"].append((packet[IP].src, packet[IP].dst))
            elif filter_option == "2":  # Analyze protocols
                if IP in packet:
                    analysis_result["protocols"].append(packet[IP].proto)
            elif filter_option == "3":  # Analyze payload data
                if Raw in packet:
                    analysis_result["payload_data"].append(packet[Raw].load.decode("utf-8", "ignore"))
            else:
                print("Invalid choice. Please try again.")
        
        return analysis_result

    except FileNotFoundError:
        print(f"Error: '{pcap_file}' not found. Please check the file path and try again.")


def generate_text_report(captured_packets, analysis_result):
    """
    Generate a text-based report based on captured packets and analysis result.
    """
    report = f"*** Packet Sniffer Tool Report ***\n\n"
    report += f"Date and Time of Capture: {datetime.datetime.now()}\n"
    report += f"Interface Used: {captured_packets['interface']}\n"
    report += f"Number of Packets Captured: {captured_packets['count']}\n\n"
    
    report += "*** Captured Packets Analysis ***\n\n"
    
    # IP Addresses Analysis
    report += "1. IP Addresses Analysis:\n"
    for src_ip, dst_ip in analysis_result["ip_addresses"]:
        report += f"- Source IP: {src_ip}, Destination IP: {dst_ip}\n"
    report += "\n"
    
    # Protocols Analysis
    report += "2. Protocols Analysis:\n"
    for proto in analysis_result["protocols"]:
        report += f"- Protocol: {proto}\n"
    report += "\n"
    
    # Payload Data Analysis
    report += "3. Payload Data Analysis:\n"
    for payload_data in analysis_result["payload_data"]:
        report += f"- Payload Data: {payload_data}\n"
    report += "\n"
    
    report += "*** Conclusion ***\n\n"
    report += "The packet sniffer tool successfully captured and analyzed the packets.\n"
    report += "Further analysis may be required based on the captured data.\n"
    
    return report


def main():
    while True:
        print("\n*** Welcome to the Packet Sniffer Tool ***")
        print("1. Capture Packets")
        print("2. Analyze Captured Packets")
        print("3. Exit")
        choice = input("Please enter your choice (1, 2, or 3): ")

        if choice == "1":
            interface = input("Enter the network interface (e.g., Ethernet or Wi-Fi): ")
            count = input("Enter the number of packets to capture (default is 10): ")
            count = int(count) if count.isdigit() else 10
            pcap_file = capture_packets(interface, count)
        elif choice == "2":
            if 'pcap_file' not in locals():
                print("Please capture packets first before analyzing.")
                continue
            
            while True:
                filter_option = input("Select analysis option:\n"
                                      "1. IP Addresses\n"
                                      "2. Protocols\n"
                                      "3. Payload Data\n"
                                      "4. Exit analysis\n"
                                      "Please enter your choice (1, 2, 3, or 4): ")
                if filter_option == "4":
                    break
                
                analysis_result = analyze_packets(pcap_file, filter_option)
                report = generate_text_report({'interface': interface, 'count': count}, analysis_result)
                print(report)
        elif choice == "3":
            print("Exiting the Packet Sniffer Tool. Goodbye!")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")


if __name__ == "__main__":
    main() 