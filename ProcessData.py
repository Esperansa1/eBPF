from subprocess import PIPE, run
import ast
import socket, struct

class ProcessData:
    def __init__(self, map_name):
        self.map_name = map_name


    def get_data(self) -> dict:
        map_data = self.get_map_data(self.map_name)
        map_data = self.process_data(map_data)
        self.process_u32_ip(map_data)
        return map_data


    def sum_total_packets(map_data: dict) -> int:
        total_packets = 0
        for packet in map_data:
            total_packets += packet['packets']
        return total_packets
    

    def get_delta_data(self, previous_data: dict) -> dict:
        new_data = self.get_data()
        for new_packet in new_data:
            for old_packet in previous_data:
                if new_packet['addr'] == old_packet['addr']:
                    new_packet['packets'] -= old_packet['packets']
                    new_packet['bytes'] -= old_packet['bytes']
        return new_data

    def u32_to_ip(self, u32_number: int) -> str:
        ip_binary = struct.pack('!L', u32_number)
        ip_binary = ip_binary[::-1] # The binary needs to be reversed
        ip_address = socket.inet_ntoa(ip_binary)
        return ip_address


    def get_map_data(self, map_name) -> str:
        command = f"sudo bpftool map dump name {map_name}"
        result = run(command, stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True)
        return result.stdout


    def process_u32_ip(self, map_data : dict) -> None:
        for packet in map_data:
            packet['addr'] = self.u32_to_ip(packet['addr'])


    def process_data(self, map_data : str) -> dict:
        map_data = ast.literal_eval(map_data)
        map_data = [packet['value'] for packet in map_data]
        return map_data

