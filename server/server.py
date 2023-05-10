import os
import pickle
import warnings
from cryptography.utils import CryptographyDeprecationWarning
from threading import Thread
import time
from queue import Queue, Empty

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
        # try:  # TODO: for some reason "if q.empty():" causes messages to be collected only when the next one is received
        if not q.empty():
            pkt = q.get(timeout=1)
            if TCP not in pkt:
                continue
            if pkt[TCP].ack == 1:
                print("ack")
                continue
            # pkt.show()
            get_packet(pkt)


def sniff_loopback(q):
    # loop back interface - iface="Software Loopback Interface 1"
    sniff(prn=lambda x: q.put(x), filter=f"dst port {personal_port}", iface=tb.loopback_interface)


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
            data = pickle.loads(load[1:])
            buffer = data[0]
            conversations[key] = [b"", buffer, data[1]]
        return
    if code == b"D":
        file_names = load[1:]
        download(key, file_names)
    if code == b"L":
        print("list request")
        send_list(key)


def send_list(key):
    entries = os.scandir("server_photos/")
    entry_list = list_from_iter(entries)
    reply(str(entry_list).encode('utf-8'), b'\x98\x16\xac', key)


def download(key, file_names):
    print(file_names)
    file_names = eval(file_names)
    for file in file_names:
        with open("server_photos/"+file, "rb") as f:
            data = f.read()
            print(len(data))
            reply(pickle.dumps([len(data), file]), b'\xa7\x98\xa8', key)
            reply(data, b'\xa7\x98\xa8', key)


def upload_request(key, load):
    global conversations
    if key not in conversations:
        raise "this is wierd"

    conversations[key][0] += load

    conversations[key][1] -= len(load)
    print("buffer:", conversations[key][1])
    if conversations[key][1] <= 0:
        upload(conversations[key][0], conversations[key][2], key)
        del conversations[key]


def upload(data, file_name, key):
    i = int(time.time() * 10000)
    with open(f"server_photos/{file_name}", "wb") as i:
        i.write(data)
        time.sleep(0.001)
    reply(b'upload complete', b'\x9d\xb7\xe3', key)


def reply(data, code_prefix, key):
    """
    Sends back replies on received messages to imitate a server
    :param code_prefix: to let other side know meaning of aproach
    :param key: consists of src#sport or received packet
    :param data: The data that is to be replied
    :return:
    """
    dst, dport = key.split("#")
    dport = int(dport)
    while len(data) > 0:
        if len(data) > 16384:
            sendable_data = code_prefix + data[:16384]
            packet = IP(dst=dst) / TCP(dport=dport, sport=personal_port) / Raw(sendable_data)
            send(packet)
            data = data[16384:]
        else:
            sendable_data = code_prefix + data
            packet = IP(dst=dst) / TCP(dport=dport, sport=personal_port) / Raw(sendable_data)
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


def list_from_iter(iter):
    l = []
    for i in iter:
        l.append(i.name)
    return l


if __name__ == '__main__':
    if len(sys.argv) > 1:
        personal_port = int(sys.argv[1])

threaded_sniff_with_send()
