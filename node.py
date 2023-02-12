import warnings
import pydivert
from cryptography.utils import CryptographyDeprecationWarning
from threading import Thread
import time
from queue import Queue, Empty

from tools.layer_new import Layer
from tools.bidict import BiDict

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
from scapy.all import *
from scapy.layers.inet import *

# CLIENT KEY - temporary
layer0 = Layer()
layer0.change_keys("0")

node_layer = Layer()

ip = "10.0.0.24"


def decrypt_packet(data):
    decrypted_data = node_layer.decrypt(data)
    return decrypted_data


def encrypt_packet(data):
    encrypted_data = layer0.b_encrypt(data)
    return encrypted_data


def stringify(lst):
    lst = map(str, lst)
    string = "['" + "', '".join(lst) + "']"
    return string


def find_next_available_port():
    global start_port
    for port in range(start_port, 65535):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(('0.0.0.0', port))
            sock.close()
            return port
        except:
            continue


def packet_handle():
    #  and not tcp.Ack and inbound
    # filter_expression = "(tcp.SrcPort == 55554 or tcp.DstPort == 55554) and outbound"
    filter_expression = "tcp"  # TODO change this filter

    prev_addr_to_ports = BiDict()  # This dictionary will convert source addresses of packets to a port to send from.

    # Open a handle to the network stack
    with pydivert.WinDivert(filter_expression) as handle:
        print("started")
        print(personal_port)
        for pkt in handle:
            if pkt.dst_port == personal_port:
                if pkt.tcp.rst:
                    continue

                print(pkt.src_addr, ":", pkt.src_port, "-->", pkt.dst_addr, ":", pkt.dst_port)
                src_addr = stringify([pkt.src_addr, pkt.src_port])

                if not prev_addr_to_ports.has_this_key(src_addr):  # If this is the first message then add it to the dict
                    available_port = find_next_available_port()
                    print(available_port)
                    prev_addr_to_ports.add(src_addr, available_port)

                # if pkt.tcp.payload:  # When packets do not have payload such as SYN packets this will not run
                load = decrypt_packet(pkt.payload)
                dst_addr, dst_port, session_id, data = load
                pkt.payload = data

                print(prev_addr_to_ports.get_value(src_addr))
                pkt.src_port = prev_addr_to_ports.get_value(src_addr)
                pkt.src_addr = ip

                pkt.dst_port = dst_port
                pkt.dst_addr = dst_addr

            elif prev_addr_to_ports.has_this_value(pkt.dst_port):
                if pkt.tcp.rst:
                    continue
                print(pkt.src_addr, ":", pkt.src_port, "-->", pkt.dst_addr, ":", pkt.dst_port)
                src_addr = stringify([pkt.src_addr, pkt.src_port])

                dst_addr, dst_port = eval(prev_addr_to_ports.get_key(pkt.dst_port))

                if pkt.tcp.payload:  # When packets do not have payload such as SYN packets this will not run
                    data = encrypt_packet(pkt.payload)
                    pkt.payload = data

                pkt.src_port = personal_port
                pkt.src_addr = ip

                pkt.dst_port = int(dst_port)
                pkt.dst_addr = dst_addr

            handle.send(pkt)


if __name__ == '__main__':
    if len(sys.argv) > 1:
        personal_port = int(sys.argv[1])
        key_num = sys.argv[2]
        start_port = int(sys.argv[3]) # this will be changed in the future
        node_layer.change_keys(key_num)
    packet_handle()
