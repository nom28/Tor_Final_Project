from scapy.all import *
from threading import Thread
import time
from queue import Queue, Empty
from scapy.layers.inet import *


from tools.layer_new import Layer

node_layer = Layer()
node_layer.change_keys("1")

finished = False


def threaded_sniff_with_send():
    q = Queue()
    sniffer = Thread(target=sniff_loopback, args=(q,))
    sniffer.daemon = True
    sniffer.start()
    time.sleep(1)  # just to make sure the sniffer doesn't override with future scapy functions.
    while not finished:
        if not q.empty():
            try:
                pkt = q.get(timeout=1)
                pkt = decrypt_packet(pkt.load)
                ip, port, session_id, data = pkt
                # print(ip, port)
                send_data(data, ip, port)
            except AttributeError:
                pass


def sniff_loopback(q):
    sniff(prn=lambda x: q.put(x), filter="dst port 55556", iface="Software Loopback Interface 1")


def decrypt_packet(data):
    decrypted_data = node_layer.decrypt(data)
    return decrypted_data


def send_data(data, ip, port):
    packet = IP(dst=ip) / TCP(dport=port, sport=55556) / Raw(data)
    send(packet)


threaded_sniff_with_send()
