from socket import *
from scapy.all import *
from scapy.layers.inet import *

with open("1mbFlower.jpg", "rb") as d:
    data = d.read()
    print(len(data))
    while len(data) > 0:
        if len(data) > 32768:
            packet = IP(dst="127.0.0.1") / TCP(dport=55656, sport=55555) / Raw(data[:32768])
            send(packet)
            data = data[32768:]
        else:
            packet = IP(dst="127.0.0.1") / TCP(dport=55656, sport=55555) / Raw(data)
            send(packet)
            packet = IP(dst="127.0.0.1") / TCP(dport=55656, sport=55555) / Raw(b"DONE")
            send(packet)
            break

# definatly unfinished, just a start of an idea to make the node code simpler
"""
class node:
    def __init__(self, host, port):
        self.ADDR = (host, port)
        self.server_socket = socket(AF_INET, SOCK_STREAM)
        self.server_socket.bind(self.ADDR)
        self.is_up = True

    def open_socket(self):
        self.server_socket.listen(3)
"""