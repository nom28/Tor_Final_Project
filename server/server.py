import os
import pickle
import warnings
from cryptography.utils import CryptographyDeprecationWarning
from threading import Thread
import time
from queue import Queue, Empty
import secrets

import tools.toolbox as tb
from tools.layer import Layer
from database.database import Database

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
from scapy.all import *
from scapy.layers.inet import *

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
_id = 40000

db = Database()
fragmented_packets = {}

layer0 = Layer()
server_layer = Layer()
key_dir = "keys/"


def boot(HOST, PORT):
    server_layer.store_keys(key_dir)
    with open(key_dir+"public_key.pem", "r") as k:
        pk = k.read()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))
    nat_ip_address = s.getsockname()[0]
    s.close()

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.bind((nat_ip_address, personal_port))
    client_socket.connect((HOST, PORT))

    message = b"S" + pickle.dumps((nat_ip_address, personal_port, "CONNECTING", pk))

    client_socket.send(message)
    response = client_socket.recv(1024).decode('utf-8')

    print(response)
    if response != "OK" and response != "REACTIVATED":
        input()

    client_socket.close()


def packet_handle():
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
            defragment_packets(pkt)
        else:
            time.sleep(0)


def sniff_loopback(q):
    # loop back interface - iface="Software Loopback Interface 1"
    sniff(prn=lambda x: q.put(x), filter=f"tcp", iface=[tb.loopback_interface, tb.main_interface])


def defragment_packets(packet):
    global fragmented_packets
    if packet.haslayer(IP):
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
            process_packet(full_packet)
        else:
            process_packet(packet)


def process_packet(packet):
    # global data
    global conversations
    global buffer  # global buffer means only one user can upload and download at the same time

    if TCP not in packet:
        return
    if packet[TCP].dport != personal_port:
        return
    if packet[TCP].ack == 1:
        print("ack")
        return

    key = packet[IP].src + "#" + str(packet[TCP].sport)
    load = packet.load

    load = decrypt_packet(load)

    code = load[:1]
    if code == b"U":
        if key in conversations:
            upload_request(key, load[1:])
        else:
            data = pickle.loads(load[1:])
            buffer = data[0]
            print("buffer:", buffer)
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
    if code == b"B":
        save_pk(key, load[1:])
        print(load[1:])
        time.sleep(1)  # This is temporary: client needs a moment to start up!
        reply(b"great", b'\xf2\xee\x07', key)


def save_pk(key, pk):
    with open(key_dir+f"public_key[{key}]".replace(".", "_") + ".pem", "wb") as k:
        k.write(pk)


def signin(key, user):
    h, auth = pickle.loads(user)
    if not db.check_user_exists(h):
        reply(b"Hash incorrect", b'\xd3\xb6\xad', key)
        return
    if not db.check_user_otp(h, auth):
        reply(b"Auth incorrect", b'\xd3\xb6\xad', key)
        return
    reply(b"sign in successful", b'\xc6\xbd\x06', key)
    sessions[key] = db.get_user_by_hash(h)[0]
    print(sessions)


def signup(key, user):
    alphabet = string.ascii_letters + string.digits
    random_hash = ''.join(secrets.choice(alphabet) for _ in range(10))

    result = db.add_user(random_hash)
    print(result)
    print(db.get_all_users())
    if result:
        sessions[key] = db.get_user_by_hash(random_hash)[0]
        print(sessions)
        os.mkdir(f"server_files/f{sessions[key]}")
        reply(pickle.dumps((random_hash, result)), b'\x9d\xf6\x9e', key)
    else:
        reply(b"User already exists", b'\xd3\xb6\xad', key)


def send_list(key):
    if key not in sessions:
        return
    user_folder = sessions[key]
    entries = os.scandir(f"server_files/f{user_folder}")
    entry_list = list_from_iter(entries)
    if "Thumbs.db" in entry_list:
        entry_list.remove("Thumbs.db")
    reply(str(entry_list).encode('utf-8'), b'\x98\x16\xac', key)


def download(key, file_names):
    if key not in sessions:
        return
    user_folder = sessions[key]
    file_names = eval(file_names)

    # blue v for accepting
    reply(b"Request accepted", b'\xf2\xee\x07', key)

    for file in file_names:
        with open(f"server_files/f{user_folder}/{file}", "rb") as f:
            data = f.read()
            print(len(data))
            reply(pickle.dumps([len(data), file]), b'\xa7\x98\xa8', key)
            reply(data, b'\xa7\x98\xa8', key)


def upload_request(key, load):
    global conversations

    if key not in sessions:
        reply(b"Not signed in", b'\xd3\xb6\xad', key)
        return

    if key not in conversations:
        raise

    conversations[key][0] += load

    conversations[key][1] -= len(load)
    print("buffer:", conversations[key][1])
    if conversations[key][1] <= 0:
        upload(conversations[key][0], conversations[key][2], key)
        del conversations[key]


def upload(data, file_name, key):
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
    global _id
    if not os.path.isfile(key_dir+f"public_key[{key}]".replace(".", "_")+".pem"):
        print("key does not exist: ", key_dir+f"public_key[{key}]".replace(".", "_")+".pem")
        return
    dst, dport = key.split("#")
    dport = int(dport)
    crop_len = 12797
    while len(data) > 0:
        if len(data) > crop_len:
            sendable_data = encrypt_packet(code_prefix + data[:crop_len], key)
            packet = IP(dst=dst, id=_id) / TCP(dport=dport, sport=personal_port) / Raw(sendable_data)
            _id += 1
            send(fragment(packet, fragsize=1400))
            data = data[crop_len:]
        else:
            sendable_data = encrypt_packet(code_prefix + data, key)
            packet = IP(dst=dst, id=_id) / TCP(dport=dport, sport=personal_port) / Raw(sendable_data)
            _id += 1
            send(fragment(packet, fragsize=1400))
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


def decrypt_packet(data):
    decrypted_data = server_layer.decrypt(data)
    return decrypted_data


def encrypt_packet(data, key):
    layer0.change_keys(key_dir, f"[{key}]".replace(".", "_"), False)
    encrypted_data = layer0.b_encrypt(data)
    return encrypted_data


if __name__ == '__main__':
    if len(sys.argv) > 1:
        personal_port = int(sys.argv[1])

boot("10.0.0.24", 55677)
packet_handle()
