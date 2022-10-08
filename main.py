from scapy.all import *
from threading import Thread
import time

data = b""
def sniff_loopback():
    sniff(prn=lambda x: add_packet(x), filter="dst port 55656", iface="Software Loopback Interface 1")


def add_packet(packet):
    global data
    if packet.load == b"DONE":
        with open("newpicture.jpg", "wb") as picture:
            picture.write(data)
    else:
        data = data + packet.load


sniff_thread = Thread(target=sniff_loopback)
sniff_thread.start()

