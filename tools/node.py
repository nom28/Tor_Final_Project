from socket import *
from scapy.all import *
from scapy.layers.inet import *



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