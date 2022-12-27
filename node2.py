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
node_layer.change_keys("2")

finished = False
previous_comp_address = []
personal_port = 55557


def threaded_sniff_with_send():
    q = Queue()
    sniffer = Thread(target=sniff_loopback, args=(q,))
    sniffer.daemon = True
    sniffer.start()
    time.sleep(1)  # just to make sure the sniffer doesn't override with future scapy functions.
    while not finished:
        if not q.empty():
            try:
                pkt = q.get(timeout=1)
                if TCP not in pkt:
                    continue
                if pkt[TCP].ack == 1:
                    print("got ack")
                    continue
                # pkt.show()
                if not previous_comp_address:
                    previous_comp_address.append(pkt[IP].src)
                    previous_comp_address.append(pkt[TCP].sport)
                pkt.show()
                if pkt[IP].src == previous_comp_address[0] and pkt[TCP].sport == previous_comp_address[1]:
                    pkt = decrypt_packet(pkt.load)
                    ip, port, session_id, data = pkt
                    send_data(data, ip, port)
                else:
                    data = encrypt_packet(pkt.load)
                    send_data(data, previous_comp_address[0], previous_comp_address[1])
                    print(f"got response:{pkt.load}")

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


threaded_sniff_with_send()
