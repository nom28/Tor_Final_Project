
from threading import Thread
import time
from queue import Queue, Empty

from tools.layer import Layer

from scapy.layers.inet import *
from scapy.all import *

data = b""
"""
layer1 = Layer()
layer1.change_keys("1")
layer2 = Layer()
layer2.change_keys("2")
"""

finished = False
previous_comp_address = []
personal_port = 55559


def threaded_sniff_with_send():
    q = Queue()
    print("initiating sniffer")
    sniffer = Thread(target=sniff_loopback, args=(q,))
    sniffer.daemon = True
    sniffer.start()
    time.sleep(1)  # just to make sure the sniffer doesn't override with future scapy functions.
    print("sniffer initiated - listening")
    while not finished:
        try:  # for some reason "if q.empty():" causes messages to be collected only when the next one is received
            pkt = q.get(timeout=1)
            if TCP not in pkt:
                continue
            if pkt[TCP].ack == 1:
                print("ack")
                continue
            # pkt.show()
            if not previous_comp_address:
                previous_comp_address.append(pkt[IP].src)
                previous_comp_address.append(pkt[TCP].sport)
            # pkt.show()

            get_packet(pkt)
        except Empty:
            pass


def sniff_loopback(q):
    # loop back interface - iface="Software Loopback Interface 1" or iface="\\Device\\NPF_Loopback"
    print(show_interfaces())
    sniff(prn=lambda x: q.put(x), filter=f"dst port {personal_port}", iface="\\Device\\NPF_Loopback")


def get_packet(packet):
    global data
    d = packet.load
    src = packet[IP].src
    sport = packet[TCP].sport
    print(d.decode())
    reply(f"echo {d.decode()}", src, sport)


def reply(data, ip, port):
    """
    Sends back replies on received messages to imitate a server
    :param data: The data that is to be replied
    :return:
    """
    while len(data) > 0:
        if len(data) > 16384:
            sendable_data = data[:16384]
            packet = IP(dst=ip) / TCP(dport=previous_comp_address[1], sport=personal_port) / Raw(sendable_data)
            print(packet.load)
            send(packet)
            data = data[16384:]
        else:
            packet = IP(dst=ip) / TCP(dport=previous_comp_address[1], sport=personal_port) / Raw(data)
            # packet.show()
            send(packet)
            # ending argument
            break
    """        
    done_argument = b"DONE"
    packet = IP(dst="127.0.0.1") / TCP(dport=previous_comp_address[1], sport=personal_port) / Raw(done_argument)
    send(packet)
    """


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

if __name__ == '__main__':
    if len(sys.argv) > 1:
        personal_port = int(sys.argv[1])

threaded_sniff_with_send()
