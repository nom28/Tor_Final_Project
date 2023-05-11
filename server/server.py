import os
import pickle
import warnings
from cryptography.utils import CryptographyDeprecationWarning
from threading import Thread
import time
from queue import Queue, Empty

import tools.toolbox as tb
from database.database import Database

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
sessions = {}
conversations = {}
buffer = 0
personal_port = 55559

db = Database()


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
        else:
            time.sleep(0)


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
        send_list(key)
    if code == b"I":
        signin(key, load[1:])
    if code == b"S":
        signup(key, load[1:])


def signin(key, user):
    email, password, auth = pickle.loads(user)
    if not db.check_user_exists(email, password):
        reply(b"Email or password incorrect", b'\xd3\xb6\xad', key)
        return
    if not db.check_user_otp(email, auth):
        reply(b"Auth incorrect", b'\xd3\xb6\xad', key)
        return
    reply(b"sign in successful", b'\xc6\xbd\x06', key)
    sessions[key] = db.get_user_by_email(email)[0]
    print(sessions)


def signup(key, user):
    email, password = pickle.loads(user)
    result = db.add_user(email, password)
    if result:
        reply(result.encode('utf-8'), b'\x9d\xf6\x9e', key)
        sessions[key] = db.get_user_by_email(email)[0]
        print(sessions)
        os.mkdir(f"server_files/f{sessions[key]}")
    else:
        reply(b"User already exists", b'\xd3\xb6\xad', key)


def send_list(key):
    if key not in sessions:
        return
    user_folder = sessions[key]
    entries = os.scandir(f"server_files/f{user_folder}")
    entry_list = list_from_iter(entries)
    reply(str(entry_list).encode('utf-8'), b'\x98\x16\xac', key)


def download(key, file_names):
    if key not in sessions:
        return
    user_folder = sessions[key]
    file_names = eval(file_names)
    for file in file_names:
        with open(f"server_files/f{user_folder}/{file}", "rb") as f:
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
    if key not in sessions:
        return
    i = int(time.time() * 10000)
    user_folder = sessions[key]
    with open(f"server_files/f{user_folder}/{file_name}", "wb") as i:
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
