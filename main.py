from subprocess import PIPE, run
import json
import ast
import socket, struct
def u32_to_ip(u32_number):
    ip_address = socket.inet_ntoa(struct.pack('!L', u32_number))
    return ip_address


def get_map_data(map_name):
    command = f"bpftool map dump name {map_name}"
    result = run(command, stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True)
    return result.stdout

def process_u32_ip(map_data : dict):
    # map_data = {key:u32_to_ip(value) for key, value in map_data.items()}
    for item in map_data:
        item['value']['addr'] = u32_to_ip(item['value']['addr'])
map_name = "packet_stats"
map_data = get_map_data(map_name)
map_data = ast.literal_eval(map_data)
process_u32_ip(map_data)
print(map_data)
