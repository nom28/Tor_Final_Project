import sys
import warnings
from cryptography.utils import CryptographyDeprecationWarning
import time
from queue import *

from tools.layer_new import Layer

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
from scapy.all import *
from scapy.layers.inet import *

layer0 = Layer()
layer0.change_keys("0")

layer1 = Layer()
layer1.change_keys("1")
layer2 = Layer()
layer2.change_keys("2")
layer3 = Layer()
layer3.change_keys("3")

session_id = random.randbytes(20)
ports = [55556, 55557, 55558, 55559]
ip = "127.0.0.1"
personal_port = 55555
finished = False


test_send_data = b"hello"


def send_data(data):
    while len(data) > 0:
        print(data)
        # time.sleep(0.1)
        if len(data) > 16384:
            encrypted_data = full_encrypt(data[:16384])
            packet = IP(dst=ip) / TCP(dport=ports[0], sport=personal_port) / Raw(encrypted_data)
            send(packet)
            data = data[16384:]
        else:
            encrypted_data = full_encrypt(data)
            packet = IP(dst=ip) / TCP(dport=ports[0], sport=personal_port) / Raw(encrypted_data)
            # packet.show()
            send(packet)
            # ending argument
            break

    done_argument = full_encrypt(b"DONE")
    packet = IP(dst=ip) / TCP(dport=ports[0], sport=personal_port) / Raw(done_argument)
    send(packet)


def full_encrypt(data):
    encrypted_data = layer3.encrypt(data, session_id, ip, str(ports[3]))
    encrypted_data = layer2.encrypt(encrypted_data, session_id, ip, str(ports[2]))
    encrypted_data = layer1.encrypt(encrypted_data, session_id, ip, str(ports[1]))
    return encrypted_data


def threaded_sniff():
    q = Queue()
    print("initiating sniffer")
    sniffer = Thread(target=sniff_loopback, args=(q,))
    sniffer.daemon = True
    sniffer.start()
    time.sleep(1)  # just to make sure the sniffer doesn't override with future scapy functions.
    print("sniffer initiated - listening")

    # ----SEND TESTING AREA----
    send_data(test_send_data)
    # -------------------------

    while not finished:
        if not q.empty():
            print("got Pkt")
            try:
                pkt = q.get()
                if TCP not in pkt:
                    continue
                if pkt[TCP].ack == 1:
                    print("ack")
                    continue
                # pkt.show()
                data = decrypt_packet(pkt.load)
                print(data)
                print("---------")
                time.sleep(0.1)
            except AttributeError:
                raise
        else:
            # do not really understand why this is needed, but does not print all packets if not.
            time.sleep(0.01)


def decrypt_packet(data):
    decrypted_data = layer0.b_decrypt(data)
    decrypted_data = layer0.b_decrypt(decrypted_data[1])
    decrypted_data = layer0.b_decrypt(decrypted_data[1])
    return decrypted_data


def sniff_loopback(q):
    sniff(prn=lambda x: q.put(x), filter=f"dst port {personal_port}", iface="Software Loopback Interface 1")


if __name__ == '__main__':
    if len(sys.argv) > 1:
        personal_port = int(sys.argv[1])
        test_send_data = bytes(sys.argv[2].encode("utf-8"))
        ports[3] = int(sys.argv[3])
    print("client started")
    threaded_sniff()

