import pydivert
import warnings
from cryptography.utils import CryptographyDeprecationWarning
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


def send_data(pkt):
    port = pkt.tcp.src_port
    dst_ip = pkt.ipv4.dst_addr
    data = pkt.payload
    while len(data) > 0:
        print(data)
        # time.sleep(0.1)
        if len(data) > 16384:
            encrypted_data = full_encrypt(data[:16384], dst_ip)
            packet = IP(dst=ip) / TCP(dport=ports[0], sport=port) / Raw(encrypted_data)
            send(packet)
            data = data[16384:]
        else:
            encrypted_data = full_encrypt(data, dst_ip)
            packet = IP(dst=ip) / TCP(dport=ports[0], sport=port) / Raw(encrypted_data)
            # packet.show()
            send(packet)
            # ending argument
            break

    """done_argument = full_encrypt(b"DONE")
    packet = IP(dst=ip) / TCP(dport=ports[0], sport=port) / Raw(done_argument)
    send(packet)"""


def full_encrypt(data, dst_ip):
    encrypted_data = layer3.encrypt(data, session_id, dst_ip, str(ports[3]))
    encrypted_data = layer2.encrypt(encrypted_data, session_id, ip, str(ports[2]))
    encrypted_data = layer1.encrypt(encrypted_data, session_id, ip, str(ports[1]))
    return encrypted_data


"""
def threaded_sniff():
    q = Queue()

    # when using pydivert, I will most likly not need to use this sniff function, and use the pydivert instead.
    print("initiating sniffer")
    sniffer = Thread(target=sniff_loopback, args=(q,))
    sniffer.daemon = True
    sniffer.start()
    time.sleep(1)  # just to make sure the sniffer doesn't override with future scapy functions.
    print("sniffer initiated - listening")


    while not finished:
        if not q.empty():
            try:
                pkt = q.get()
                if TCP not in pkt:
                    continue
                if pkt[TCP].ack == 1:
                    print("ack")
                    continue
                pkt.show()
                data = decrypt_packet(pkt.load)
                # print(data)
                print("---------")
                time.sleep(0.1)
            except AttributeError:
                raise
        else:
            # do not really understand why this is needed, but does not print all packets if not.
            time.sleep(0.01)
"""


def decrypt_packet(data):
    decrypted_data = layer0.b_decrypt(data)
    decrypted_data = layer0.b_decrypt(decrypted_data[1])
    decrypted_data = layer0.b_decrypt(decrypted_data[1])
    return decrypted_data


"""
def sniff_loopback(q):
    sniff(prn=lambda x: q.put(x), filter=f"dst port {personal_port}", iface="\\Device\\NPF_Loopback")
"""

def packet_handle():
    #  and not tcp.Ack and inbound
    # filter_expression = "(tcp.SrcPort == 55554 or tcp.DstPort == 55554) and outbound"
    filter_expression = "tcp"

    # Open a handle to the network stack
    with pydivert.WinDivert(filter_expression) as handle:
        for pkt in handle:
            print(pkt.ip.dst_addr)
            print(pkt.ip.src_addr)
            # Access packet information
            if pkt.tcp.src_port == 55554:
                print("--------------------")
                print(pkt.tcp.src_port)
                print(pkt.tcp.dst_port)
                print("--------------------")
                data = pkt.payload
                encrypted_data = full_encrypt(data, pkt.ipv4.dst_addr)
                pkt.payload = encrypted_data
                pkt.tcp.dst_port = ports[0]
            elif pkt.tcp.dst_port == 55554:
                print("--------------------")
                print(pkt.tcp.src_port)
                print(pkt.tcp.dst_port)
                print("--------------------")
                if pkt.tcp.ack:
                    handle.send(pkt)
                    continue
                print(pkt.payload)
                try:
                    data = decrypt_packet(pkt.payload)
                    pkt.payload = data
                except ValueError:
                    print("A terrible Error has accured.")
            else:
                print("rogue packet")
            # handle.send(pkt)


if __name__ == '__main__':
    if len(sys.argv) > 1:
        personal_port = int(sys.argv[1])
        test_send_data = bytes(sys.argv[2].encode("utf-8"))
        ports[3] = int(sys.argv[3])
    print("client started")
    # threaded_sniff()
    packet_handle()

