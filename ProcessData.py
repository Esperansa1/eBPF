from subprocess import PIPE, run
import ast
import socket, struct

class ProcessData:
    def __init__(self, map_name):
        self.map_name = map_name


    def get_data(self) -> list:
        map_data = self.get_map_data(self.map_name)
        map_data = self.process_data(map_data)
        self.process_u32_ip(map_data)
        return map_data

    def get_ip_data(self, ip) -> dict:
        data = self.get_data()
        for packet in data:
            if packet['addr'] == ip:
                return packet
        return None


    def sum_total_packets(self, map_data: list) -> int:
        total_packets = 0
        for packet in map_data:
            total_packets += packet['packets']
        return total_packets
    
    def sum_total_bytes(self, map_data: list) -> int:
        total_packets = 0
        for packet in map_data:
            total_packets += packet['bytes']
        return total_packets

    def get_delta_data(self, new_data: list, previous_data: list) -> dict:
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
                    break
        return delta_data

    def u32_to_ip(self, u32_number: int) -> str:
        ip_binary = struct.pack('!L', u32_number)
        ip_binary = ip_binary[::-1] # The binary needs to be reversed
        ip_address = socket.inet_ntoa(ip_binary)
        return ip_address


    def get_map_data(self, map_name) -> str:
        command = f"sudo bpftool map dump name {map_name}"
        result = run(command, stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True)
        return result.stdout


    def process_u32_ip(self, map_data : list) -> None:
        for packet in map_data:
            packet['addr'] = self.u32_to_ip(packet['addr'])


    def process_data(self, map_data : str) -> list:
        map_data = ast.literal_eval(map_data)
        map_data = [packet['value'] for packet in map_data]
        return map_data
