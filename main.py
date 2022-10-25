from scapy.all import *
from threading import Thread
import time
from queue import Queue, Empty

from tools.layer import Layer

data = b""
"""
layer1 = Layer()
layer1.change_keys("1")
layer2 = Layer()
layer2.change_keys("2")
layer3 = Layer()
layer3.change_keys("3")
"""
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
            get_packet(pkt)
        except Empty:
            pass


def sniff_loopback(q):
    sniff(prn=lambda x: q.put(x), filter="dst port 55559", iface="Software Loopback Interface 1")


def get_packet(packet):
    global data
    d = packet.load
    print(d)

    # only for pictures
    """if d == b"DONE":
        with open("newpicture.jpg", "wb") as picture:
            picture.write(data)
    else:
        data = data + d"""


"""
def decrypt_packet(data):
    decrypted_data = layer3.decrypt(layer2.decrypt(layer1.decrypt(data)))
    print(decrypted_data)
    return decrypted_data
"""


threaded_sniff_with_send()
