from scapy.all import *
from threading import Thread
import time
from queue import Queue, Empty
from scapy.layers.inet import *


from tools.layer import Layer

data = b""
node_layer = Layer()
node_layer.change_keys("3")

finished = False


def threaded_sniff_with_send():
    q = Queue()
    sniffer = Thread(target=sniff_loopback, args=(q,))
    sniffer.daemon = True
    sniffer.start()
    time.sleep(1)  # just to make sure the sniffer doesn't override with future scapy functions.
    while not finished:
        try:
            pkt = q.get(timeout=1)
            pkt = decrypt_packet(pkt.load)
            send_data(pkt)
        except (Empty, AttributeError):
            pass


def sniff_loopback(q):
    sniff(prn=lambda x: q.put(x), filter="dst port 55558", iface="Software Loopback Interface 1")


def decrypt_packet(data):
    decrypted_data = node_layer.decrypt(data)
    return decrypted_data


def send_data(data):
    packet = IP(dst="127.0.0.1") / TCP(dport=55559, sport=55558) / Raw(data)
    send(packet)


threaded_sniff_with_send()
