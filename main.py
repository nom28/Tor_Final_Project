from scapy.all import *
from threading import Thread
import time

from tools.layer import Layer

data = b""
layer1 = Layer()
layer1.change_keys("1")
layer2 = Layer()
layer2.change_keys("2")
layer3 = Layer()
layer3.change_keys("3")

data_list = []
def sniff_loopback():
    sniff(prn=lambda x: add_packet(x), filter="dst port 55656", iface="Software Loopback Interface 1")

def add_packet(packet):
    global data
    d = decrypt_packet(packet.load)
    if d == b"DONE":
        with open("newpicture.jpg", "wb") as picture:
            picture.write(data)
    else:
        data = data + d


def decrypt_packet(data):
    decrypted_data = layer3.decrypt(layer2.decrypt(layer1.decrypt(data)))
    print(decrypted_data)
    return decrypted_data


sniff_thread = Thread(target=sniff_loopback)
sniff_thread.start()
