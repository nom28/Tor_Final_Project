import warnings
from cryptography.utils import CryptographyDeprecationWarning
from threading import Thread
import time
from queue import Queue, Empty

from tools.layer_new import Layer

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
from scapy.all import *
from scapy.layers.inet import *


# CLIENT KEY - temporary
layer0 = Layer()
layer0.change_keys("0")

node_layer = Layer()

finished = False
previous_comp_address = []

sk_to_dst = {}
src_to_sk = {}


def threaded_sniff_with_send():
    q = Queue()
    print("initiating sniffer")
    sniffer = Thread(target=sniff_loopback, args=(q,))
    sniffer.daemon = True
    sniffer.start()
    time.sleep(1)  # just to make sure the sniffer doesn't override with future scapy functions.
    print("sniffer initiated - listening")
    while not finished:
        if not q.empty():
            try:
                pkt = q.get(timeout=1)
                if TCP not in pkt:
                    continue
                if pkt[TCP].ack == 1:
                    print("ack")
                    continue
                # pkt.show()
                src = pkt[IP].src
                sport = pkt[TCP].sport
                pkt_address = stringify([src, sport])
                print(pkt_address)
                if not previous_comp_address:
                    previous_comp_address.append(src)
                    previous_comp_address.append(sport)
                # if src == previous_comp_address[0] and sport == previous_comp_address[1]:
                if pkt_address in sk_to_dst.values() or pkt_address not in src_to_sk:
                    pkt = decrypt_packet(pkt.load)
                    ip, port, session_id, data = pkt

                    if session_id not in src_to_sk.values():
                        src_to_sk[stringify([ip, port])] = session_id
                    if session_id not in sk_to_dst:
                        sk_to_dst[session_id] = pkt_address

                    send_data(data, ip, port)
                    print(f"{key_num}-->")
                else:
                    if pkt_address not in src_to_sk:
                        print("very interesting")
                        exit()
                    session_id = src_to_sk[pkt_address]
                    address = eval(sk_to_dst[session_id])
                    data = encrypt_packet(pkt.load)
                    send_data(data, address[0], int(address[1]))
                    print(f"{address}<--{key_num}")
            except AttributeError:
                pass


def sniff_loopback(q):
    sniff(prn=lambda x: q.put(x), filter=f"dst port {personal_port}", iface="Software Loopback Interface 1")


def decrypt_packet(data):
    decrypted_data = node_layer.decrypt(data)
    return decrypted_data


def encrypt_packet(data):
    encrypted_data = layer0.b_encrypt(data)
    return encrypted_data


def send_data(data, ip, port):
    packet = IP(dst=ip) / TCP(dport=port, sport=personal_port) / Raw(data)
    send(packet)


def stringify(lst):
    lst = map(str, lst)
    string = "['"+"', '".join(lst)+"']"
    return string


if __name__ == '__main__':
    if len(sys.argv) > 1:
        personal_port = int(sys.argv[1])
        key_num = sys.argv[2]

        node_layer.change_keys(key_num)
    threaded_sniff_with_send()
