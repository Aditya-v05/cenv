from flask import Flask, render_template, jsonify, url_for
from scapy.all import sniff, IP, TCP, UDP, DNS, Raw, ICMP
import pymongo
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)

# Connect to MongoDB
client = pymongo.MongoClient("mongodb://localhost:27017/")  # Default MongoDB URL
db = client["network_traffic_db"]
packets_collection = db["packets"]

# Function to process and save each packet
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        src_port = None
        dst_port = None
        extra_data = ""

        # Check if the packet is TCP or UDP
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # Capture higher-layer protocol data (e.g., DNS, ICMP)
        if DNS in packet:
            try:
                query_name = packet[DNS].qd.qname.decode(errors='ignore')
                extra_data = f"DNS Query: {query_name}"
            except Exception as e:
                extra_data = f"Error decoding DNS query: {str(e)}"
        elif ICMP in packet:
            extra_data = "ICMP Packet"
        elif Raw in packet:
            try:
                extra_data = packet[Raw].load.decode(errors='ignore')
            except Exception as e:
                extra_data = f"Error decoding raw data: {str(e)}"

        # Prepare packet data
        packet_data = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip_src,
            "dst_ip": ip_dst,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,
            "extra_data": extra_data
        }

        # Insert packet data into MongoDB
        try:
            packets_collection.insert_one(packet_data)
            print(f"Captured packet: {ip_src} -> {ip_dst} | Protocol: {protocol}")
        except Exception as e:
            print(f"Error inserting packet into MongoDB: {e}")

# Start packet capture
def start_packet_capture():
    sniff(iface="Intel(R) Wi-Fi 6 AX201 160MHz", prn=packet_callback, store=0)  # Replace 'eth0' with your network interface

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/packets', methods=['GET'])
def get_packets():
    # Fetch all packets from MongoDB
    packets = packets_collection.find({}, {"_id": 0})  # Exclude MongoDB's default '_id' field
    packets_json = [packet for packet in packets]
    return jsonify(packets_json)

if __name__ == '__main__':
    # Start packet capture in the background
    from threading import Thread
    capture_thread = Thread(target=start_packet_capture)
    capture_thread.daemon = True  # Allow the capture thread to exit when the main program exits
    capture_thread.start()

    # Run the Flask app
    app.run(debug=True, use_reloader=False)  # Use reloader=False to prevent the app from restarting twice
