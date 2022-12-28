from scapy.all import *
from threading import Thread
import time
from queue import Queue, Empty
from scapy.layers.inet import *

from tools.layer_new import Layer


# CLIENT KEY - temporary
layer0 = Layer()
layer0.change_keys("0")

node_layer = Layer()

finished = False
previous_comp_address = []


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
                if not previous_comp_address:
                    previous_comp_address.append(pkt[IP].src)
                    previous_comp_address.append(pkt[TCP].sport)
                if pkt[IP].src == previous_comp_address[0] and pkt[TCP].sport == previous_comp_address[1]:
                    pkt = decrypt_packet(pkt.load)
                    ip, port, session_id, data = pkt
                    send_data(data, ip, port)
                    print("-->")
                else:
                    data = encrypt_packet(pkt.load)
                    send_data(data, previous_comp_address[0], previous_comp_address[1])
                    print(f"<--")
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


if __name__ == '__main__':
    if len(sys.argv) > 1:
        personal_port = int(sys.argv[1])
        key_num = sys.argv[2]

        node_layer.change_keys(key_num)
    threaded_sniff_with_send()
