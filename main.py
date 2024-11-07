from ProcessData import ProcessData
from Visualizer import Visualizer
import time
import os

logo = """
███████╗██████╗ ██████╗ ███████╗    ██████╗ ██████╗  ██████╗      ██╗███████╗ ██████╗████████╗ 
██╔════╝██╔══██╗██╔══██╗██╔════╝    ██╔══██╗██╔══██╗██╔═══██╗     ██║██╔════╝██╔════╝╚══██╔══╝ 
█████╗  ██████╔╝██████╔╝█████╗      ██████╔╝██████╔╝██║   ██║     ██║█████╗  ██║        ██║    
██╔══╝  ██╔══██╗██╔═══╝ ██╔══╝      ██╔═══╝ ██╔══██╗██║   ██║██   ██║██╔══╝  ██║        ██║    
███████╗██████╔╝██║     ██║         ██║     ██║  ██║╚██████╔╝╚█████╔╝███████╗╚██████╗   ██║    
╚══════╝╚═════╝ ╚═╝     ╚═╝         ╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚════╝ ╚══════╝ ╚═════╝   ╚═╝    
                                                                                               
 ██████╗ ██████╗     ███████╗███████╗██████╗ ███████╗██████╗  █████╗ ███╗   ██╗███████╗ █████╗ 
██╔═══██╗██╔══██╗    ██╔════╝██╔════╝██╔══██╗██╔════╝██╔══██╗██╔══██╗████╗  ██║██╔════╝██╔══██╗
██║   ██║██████╔╝    █████╗  ███████╗██████╔╝█████╗  ██████╔╝███████║██╔██╗ ██║███████╗███████║
██║   ██║██╔══██╗    ██╔══╝  ╚════██║██╔═══╝ ██╔══╝  ██╔══██╗██╔══██║██║╚██╗██║╚════██║██╔══██║
╚██████╔╝██║  ██║    ███████╗███████║██║     ███████╗██║  ██║██║  ██║██║ ╚████║███████║██║  ██║
 ╚═════╝ ╚═╝  ╚═╝    ╚══════╝╚══════╝╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
"""


visualizer = Visualizer()
data_processor = ProcessData("packet_stats")


def average_load(total_packet_logs):
    return int(sum(total_packet_logs) / len(total_packet_logs))

def detect_anomalies(total_packet_logs, total_packets):
    if total_packets > average_load(total_packet_logs) * 2:
        print("Anomaly detected in last data patch")



def visualize_network_load():
    delay = 1
    previous_data = data_processor.get_data()
    time.sleep(delay)
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

def visualize_ip_load():
    pass

if __name__ == "__main__":
    print(logo)
    time.sleep(1)
    os.system("cls || clear ")
    print("1. Visualzie network load")
    print("2. Visualize IP load")
    user_input = int(input("Enter: "))
    if user_input == 1:
        visualize_network_load()
    elif user_input == 2:
        ip = input("Enter wanted IP: ")
        visualize_ip_load(ip)