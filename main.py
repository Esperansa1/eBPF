from ProcessData import ProcessData
from Visualizer import Visualizer
import matplotlib.pyplot as plt 
import time

visualizer = Visualizer()
data_processor = ProcessData("packet_stats")

# time.sleep(1) # Because python3 sends a couple of packets which may make graph weird

delay = 1
previous_data = data_processor.get_data()
time.sleep(delay)

def average_load(total_packet_logs):
    return int(sum(total_packet_logs) / len(total_packet_logs))

def detect_anomalies(total_packet_logs, total_packets):
    if total_packets > average_load(total_packet_logs) * 2:
        print("Anomaly detected in last data patch")



total_packet_logs = []

while True:
    new_data = data_processor.get_data()
    delta_data = data_processor.get_delta_data(new_data, previous_data)

    total_packets = data_processor.sum_total_packets(delta_data)
    total_packet_logs.append(total_packets)

    detect_anomalies(total_packet_logs, total_packets)

    previous_data = new_data
    visualizer.visualize_network_load(total_packets)
    # visualizer.visualize_ip_load(delta_data, '10.2.0.6')
    time.sleep(delay)
    