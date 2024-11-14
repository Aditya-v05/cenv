from scapy.all import sniff, IP, TCP, UDP
import sqlite3
import time

# Connect to SQLite database (this will create the database if it doesn't exist)
conn = sqlite3.connect("network_traffic.db")
cursor = conn.cursor()

# Create a table to store packet data if it doesn't exist
cursor.execute('''
CREATE TABLE IF NOT EXISTS packets (
    timestamp TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    protocol TEXT,
    src_port INTEGER,
    dst_port INTEGER
)
''')
conn.commit()

# Function to process and store each packet
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        src_port = None
        dst_port = None
        
        # Check if the packet is TCP or UDP and extract ports
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        
        # Save packet data to the SQLite database
        cursor.execute('''
        INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, src_port, dst_port) 
        VALUES (datetime('now'), ?, ?, ?, ?, ?)
        ''', (ip_src, ip_dst, protocol, src_port, dst_port))
        conn.commit()
        
        # Print packet data to the terminal
        print(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')} | "
              f"Source IP: {ip_src} | Destination IP: {ip_dst} | "
              f"Protocol: {protocol} | Source Port: {src_port} | Destination Port: {dst_port}")

# Function to display all stored packets
def show_stored_packets():
    cursor.execute("SELECT * FROM packets")
    rows = cursor.fetchall()
    
    if rows:
        print("\nStored Network Traffic:")
        for row in rows:
            print(f"Timestamp: {row[0]} | Source IP: {row[1]} | Destination IP: {row[2]} | "
                  f"Protocol: {row[3]} | Source Port: {row[4]} | Destination Port: {row[5]}")
    else:
        print("No packets found in the database.")

# Function to start packet sniffing and display data in terminal
def start_packet_sniffing():
    print("Starting packet capture. Press Ctrl+C to stop.")
    sniff(prn=packet_callback, store=0)  # sniff on all packets, and call packet_callback on each one

if __name__ == "__main__":
    # Option to view stored packets or start sniffing
    print("Select an option:")
    print("1. Start packet sniffing")
    print("2. Show all captured packets")
    
    choice = input("Enter your choice (1/2): ")
    
    if choice == '1':
        start_packet_sniffing()
    elif choice == '2':
        show_stored_packets()
    else:
        print("Invalid choice. Exiting.")
