import struct
import warnings


from cryptography.utils import CryptographyDeprecationWarning
from threading import Thread
import time
from queue import Queue, Empty

from tools.layer import Layer
from tools.bidict import BiDict
import tools.toolbox as tb

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
from scapy.all import *
from scapy.layers.inet import *


# CLIENT KEY - temporary
layer0 = Layer()
layer0.change_keys("0", False)

node_layer = Layer()

finished = False
prev_addr_to_ports = BiDict()
fragmented_packets = {}
_id = 1


def threaded_sniff_with_send():
    q = Queue()

    print("initiating sniffer")
    sniffer = Thread(target=sniff_loopback, args=(q,))
    sniffer.daemon = True
    sniffer.start()
    time.sleep(1)  # just to make sure the sniffer doesn't override with future scapy functions.
    print("sniffer initiated - listening")

    while not finished:
        if not q.empty():
            pkt = q.get(timeout=1)
            defragment_packets(pkt)
        else:
            time.sleep(0)


def defragment_packets(packet):
    global fragmented_packets
    if not packet.haslayer(IP):
        return
    ip = packet[IP]
    if ip.flags == 1:  # Fragmentation flag is set
        if tb.stringify([ip.id, ip.src]) not in fragmented_packets:
            fragmented_packets[tb.stringify([ip.id, ip.src])] = [packet]
        else:
            fragmented_packets[tb.stringify([ip.id, ip.src])].append(packet)
    elif ip.flags == 0 and tb.stringify([ip.id, ip.src]) in fragmented_packets:  # Last fragment
        fragmented_packets[tb.stringify([ip.id, ip.src])].append(packet)

        fragments = fragmented_packets.pop(tb.stringify([ip.id, ip.src]))
        fragments = sorted(fragments, key=lambda x: x[IP].frag)
        full_packet = fragments[0]
        payload = b''
        for fragment in fragments:  # Sort fragments by offset
            payload += fragment.load
        full_packet.load = payload

        full_packet[IP].flags = 0

        process_packet(full_packet)
    else:
        process_packet(packet)


def process_packet(pkt):
    global start_port
    global prev_addr_to_ports
    # Checks if is a data TCP packet
    if TCP not in pkt:
        return
    if pkt[TCP].flags.R:
        return
    if pkt[TCP].flags.A:
        return
    dport = pkt[TCP].dport
    sport = pkt[TCP].sport
    src = pkt[IP].src
    src_address = tb.stringify([src, sport])

    if dport == personal_port:
        if not prev_addr_to_ports.has_this_key(src_address):  # If this is the first message then add it to the dict
            available_port = tb.find_next_available_port(start_port)
            start_port += 1
            prev_addr_to_ports.add(src_address, available_port)

        pkt = decrypt_packet(pkt.load)

        ip, port, session_id, data = pkt  # session key becomes redundant
        print(f"{key_num}-->{ip}:{port}")
        send_data(data, ip, port, prev_addr_to_ports.get_value(src_address))
    elif prev_addr_to_ports.has_this_value(dport):
        ip, port = eval(prev_addr_to_ports.get_key(dport))
        print(f"{ip}:{port}<--{key_num}")
        data = encrypt_packet(pkt.load)
        send_data(data, ip, int(port), personal_port)


# "Software Loopback Interface 1"
def sniff_loopback(q):
    sniff(prn=lambda x: q.put(x), filter="tcp", iface=[tb.loopback_interface, tb.main_interface])


def decrypt_packet(data):
    decrypted_data = node_layer.decrypt(data)
    return decrypted_data


def encrypt_packet(data):
    encrypted_data = layer0.b_encrypt(data)
    return encrypted_data


def send_data(data, ip, port, cport):
    global _id
    packet = IP(dst=ip, id=_id) / TCP(dport=port, sport=cport) / Raw(data)
    _id += 1
    a = fragment(packet, fragsize=1400)
    print(packet.load)
    send(a)


if __name__ == '__main__':
    if len(sys.argv) > 1:
        personal_port = int(sys.argv[1])
        start_port = int(sys.argv[2])
        key_num = sys.argv[3]
        _id *= int(key_num)
        node_layer.change_keys(key_num, True)
    threaded_sniff_with_send()
