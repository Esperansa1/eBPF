from ProcessData import ProcessData
from Visualizer import Visualizer
import time
import datetime
import os
from config import LOG_FOLDER, INTERVAL, LOGO, ANOMALY_PACKET_THRESHOLD_PRECENT

visualizer = Visualizer()
data_processor = ProcessData("packet_stats")

def average_load(total_packet_logs):
    return int(sum(total_packet_logs) / len(total_packet_logs))

# Detect an anomaly if a average_packet_load * THRESHOLD% < current_packet_load
# Logs data to 
def detect_anomalies(log_folder_path: str, total_packet_logs: list, current_total_packets: int):
    average_packet_load = average_load(total_packet_logs)

    packet_threshold = average_packet_load * ANOMALY_PACKET_THRESHOLD_PRECENT
    if current_total_packets > packet_threshold:
        now = datetime.datetime.now()
        time_formatted = now.strftime("%Y-%m-%d %H:%M:%S")
        with open(log_folder_path, "a") as f:
            f.write(f"{time_formatted} Packet spike with {current_total_packets} packets. Average load was {average_packet_load}\n")


def analyze_network_load(interval, log_folder_path):    
    previous_data = data_processor.get_data()
    total_packet_logs = []
    while True:
        new_data = data_processor.get_data()
        delta_data = data_processor.get_delta_data(new_data, previous_data)

        total_packets = data_processor.sum_total_packets(delta_data)
        total_packet_logs.append(total_packets)
        
        # After a little bit of network logging to assure network stability
        detect_anomalies(log_folder_path, total_packet_logs, total_packets)
        
        previous_data = new_data
        visualizer.visualize_data(total_packets)
        time.sleep(interval)

def analyze_ip_load(interval, log_folder_path, target_ip):
    previous_data = data_processor.get_ip_data(target_ip)
    total_packet_logs = []
    while True:
        new_data = data_processor.get_ip_data(target_ip)
        
        delta_packets = new_data['packets'] - previous_data['packets']
        total_packet_logs.append(delta_packets)
        
        # After a little bit of network logging to assure network stability
        detect_anomalies(log_folder_path, total_packet_logs, delta_packets)
        
        previous_data = new_data
        visualizer.visualize_data(delta_packets)
        time.sleep(interval)

if __name__ == "__main__":
    os.system("cls || clear")

    print(LOGO)
    time.sleep(INTERVAL)
    
    #Clear terminal
    os.system("cls || clear")
    
    print("1. Visualize network load")
    print("2. Visualize IP load")
    
    user_input = int(input("Enter: "))
    if user_input == 1:
        analyze_network_load(INTERVAL, LOG_FOLDER)
    elif user_input == 2:
        target_ip = input("Enter wanted IP: ")
        analyze_ip_load(INTERVAL, LOG_FOLDER, target_ip)