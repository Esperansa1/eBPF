from subprocess import PIPE, run
import ast
import socket, struct

class ProcessData:
    def __init__(self, map_name):
        self.map_name = map_name

    # returns the data of all addresses 
    def get_data(self) -> list[dict]:
        map_data = self.get_map_data(self.map_name)
        map_data = self.process_data(map_data)
        self.process_u32_ip(map_data)
        return map_data

    # returns the data of a specific ip address
    def get_ip_data(self, ip) -> dict:
        data = self.get_data()
        for packet in data:
            if packet['addr'] == ip:
                return packet
        return None


    # sums total packets in the list of dictionaries
    def sum_total_packets(self, map_data: list[dict]) -> int:
        total_packets = 0
        for packet in map_data:
            total_packets += packet['packets']
        return total_packets
    
    # sums total bytes in the list of dictionaries
    def sum_total_bytes(self, map_data: list[dict]) -> int:
        total_packets = 0
        for packet in map_data:
            total_packets += packet['bytes']
        return total_packets


    # returns the difference in data between new_data and previous_data
    def get_delta_data(self, new_data: list[dict], previous_data: list[dict]) -> dict:
        delta_data = []
        for new_packet in new_data:
            for old_packet in previous_data:
                if new_packet['addr'] == old_packet['addr']:
                    delta_packet = {}
                    delta_packet['packets'] = new_packet['packets'] - old_packet['packets']
                    delta_packet['bytes'] = new_packet['bytes'] - old_packet['bytes']
                    delta_packet['addr'] = new_packet['addr']
                    if delta_packet['packets'] != 0 and delta_packet['bytes'] != 0: # Don't write unchanged data
                        delta_data.append(delta_packet)
                    break # only 1 matching address per list so no need to keep iterating
        return delta_data

    # converts a u32 number which represents the IP to a human readable IP string
    def u32_to_ip(self, u32_number: int) -> str:
        ip_binary = struct.pack('<L', u32_number) # Converts u32 number to binary
        # ip_binary = ip_binary[::-1] # The binary needs to be reversed
        ip_address = socket.inet_ntoa(ip_binary) # Converts the binary into IP format
        return ip_address


    # returns the data from a given BPF Map
    def get_map_data(self, map_name) -> str:
        command = f"sudo bpftool map dump name {map_name}"
        result = run(command, stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True)
        return result.stdout

    # iterates through the list and converts each u32 to ip format
    def process_u32_ip(self, map_data : list[dict]) -> None:
        for packet in map_data:
            packet['addr'] = self.u32_to_ip(packet['addr'])

    # gets a string in a dictionary format and converts it into a list of dictionaries
    def process_data(self, map_data : str) -> list[dict]:
        map_data = ast.literal_eval(map_data)
        map_data = [packet['value'] for packet in map_data] # gets rid of reduandent key field
        return map_data
