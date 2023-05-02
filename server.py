import warnings
from cryptography.utils import CryptographyDeprecationWarning
from threading import Thread
import time
from queue import Queue, Empty

from tools.layer import Layer
import tools.toolbox as tb

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
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
conversations = {}
buffer = 0
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
    # loop back interface - iface="Software Loopback Interface 1"
    sniff(prn=lambda x: q.put(x), filter=f"dst port {personal_port}", iface="\\Device\\NPF_Loopback")


def get_packet(packet):
    # global data
    global conversations
    global buffer  # global buffer means only one user can upload and download at the same time

    key = packet[IP].src + "#" + str(packet[TCP].sport)
    load = packet.load

    code = load[:1]
    if code == b"U":
        if key in conversations:
            upload_request(key, load[1:])
        else:
            buffer = tb.int_from_bytes(load[1:])
            conversations[key] = [b"", buffer]
        return
    if code == b"D":
        file_name = load[1:]
        download(key, file_name)
    if code == b"L":
        page_number = load[1:]
        send_list(key, page_number)


def send_list(key, load):
    pass


def download(key, load):
    pass


def upload_request(key, load):
    global conversations
    if key not in conversations:
        raise "this is wierd"

    conversations[key][0] += load

    conversations[key][1] -= len(load)
    print("buffer:", conversations[key][1])
    if conversations[key][1] <= 0:
        upload(conversations[key][0])
        del conversations[key]


def upload(data):
    i = int(time.time() * 10000)
    with open(f"server_photos/file_{i}.jpg", "wb") as i:
        i.write(data)
        time.sleep(0.001)
    reply(b'\x9d\xb7\xe3upload complete')


def reply(data):
    """
    Sends back replies on received messages to imitate a server
    :param data: The data that is to be replied
    :return:
    """
    while len(data) > 0:
        if len(data) > 16384:
            sendable_data = data[:16384]
            packet = IP(dst="127.0.0.1") / TCP(dport=previous_comp_address[1], sport=personal_port) / Raw(sendable_data)
            send(packet)
            data = data[16384:]
        else:
            packet = IP(dst="127.0.0.1") / TCP(dport=previous_comp_address[1], sport=personal_port) / Raw(data)
            # packet.show()
            send(packet)
            break


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
