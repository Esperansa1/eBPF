from ProcessData import ProcessData
from Visualizer import Visualizer
import time
import datetime
visualizer = Visualizer()
data_processor = ProcessData("packet_stats")

# time.sleep(1) # Because python3 sends a couple of packets which may make graph weird

def average_load(total_packet_logs):
    return int(sum(total_packet_logs) / len(total_packet_logs))

def detect_anomalies(total_packet_logs, total_packets):
    average_packet_load = average_load(total_packet_logs)

    packet_threshold = average_packet_load * 1.2
    if total_packets > packet_threshold:
        now = datetime.datetime.now()
        time_formatted = now.strftime("%Y-%m-%d %H:%M:%S")
        with open("packet_logs.txt", "a") as f:
            f.write(f"{time_formatted} Packet spike with {total_packets} packets. Average load was {average_packet_load}\n")

delay = 1
previous_data = data_processor.get_data()
time.sleep(delay)

total_packet_logs = []

i = 0
while True:
    new_data = data_processor.get_data()
    delta_data = data_processor.get_delta_data(new_data, previous_data)

    total_packets = data_processor.sum_total_packets(delta_data)
    total_packet_logs.append(total_packets)
    
     # After a little bit of network logging to assure network stability
    detect_anomalies(total_packet_logs, total_packets)

    previous_data = new_data
    # visualizer.visualize_network_load(total_packets)
    # visualizer.visualize_ip_load(delta_data, '10.2.0.6')
    time.sleep(delay)
    