import warnings
from cryptography.utils import CryptographyDeprecationWarning
from queue import *

from tools.layer import Layer
import tools.toolbox as tb

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
from scapy.all import *
from scapy.layers.inet import *


class Client:
    layer0 = Layer()
    layer1 = Layer()
    layer2 = Layer()
    layer3 = Layer()

    q = Queue()

    session_id = random.randbytes(20)
    ip = tb.addresses[0][0]
    personal_port = tb.addresses[0][1]
    finished = False
    fragmented_packets = {}
    _id = 1

    test_send_data = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-="*300

    def __init__(self):
        self.layer0.change_keys("0", True)
        self.layer1.change_keys("1", False)
        self.layer2.change_keys("2", False)
        self.layer3.change_keys("3", False)

    def sniffer(self, d):
        print("initiating sniffer")
        sniffer = Thread(target=self.sniff_loopback)
        sniffer.daemon = True
        sniffer.start()
        time.sleep(0.001)  # just to make sure the sniffer doesn't override with future scapy functions.
        print("sniffer initiated - listening")

        while not self.finished:
            if not self.q.empty():
                try:
                    pkt = self.q.get()
                    self.defragment_packets(pkt, d)
                except AttributeError:
                    raise
            else:
                # do not really understand why this is needed, but does not print all packets if not.
                time.sleep(0)

    def sniff_loopback(self):
        sniff(prn=lambda x: self.q.put(x), filter=f"tcp", iface=[tb.loopback_interface, tb.main_interface])

    def defragment_packets(self, packet, d):
        if packet.haslayer(IP):
            ip = packet[IP]
            if ip.flags == 1:  # Fragmentation flag is set
                if tb.stringify([ip.id, ip.src]) not in self.fragmented_packets:
                    self.fragmented_packets[tb.stringify([ip.id, ip.src])] = [packet]
                else:
                    print("frag:", packet[IP].frag)
                    self.fragmented_packets[tb.stringify([ip.id, ip.src])].append(packet)
            elif ip.flags == 0 and tb.stringify([ip.id, ip.src]) in self.fragmented_packets:  # Last fragment
                self.fragmented_packets[tb.stringify([ip.id, ip.src])].append(packet)
                fragments = self.fragmented_packets.pop(tb.stringify([ip.id, ip.src]))
                fragments = sorted(fragments, key=lambda x: x[IP].frag)
                full_packet = fragments[0]
                payload = b''
                print("----")
                for fragment in fragments:  # Sort fragments by offset
                    print(fragment)
                    payload += fragment.load
                full_packet.load = payload
                self.process_packet(full_packet, d)
            else:
                self.process_packet(packet, d)

    def process_packet(self, pkt, d):
        if TCP not in pkt:
            return
        if pkt[TCP].ack == 1:
            return
        if pkt[TCP].dport != self.personal_port:
            return
        # pkt.show()
        data = self.decrypt_packet(pkt.load)
        d.put(data[1])  # [0] is session key

    def send(self, data, code_prefix):
        while len(data) > 0:
            # time.sleep(0.1)
            print("sending")
            crop_len = 10239  # 10240 - 1 (code prefix)
            if len(data) > crop_len:
                encrypted_data = self.full_encrypt(code_prefix + data[:crop_len])
                packet = IP(dst=tb.addresses[1][0], id=self._id) / TCP(dport=tb.addresses[1][1], sport=self.personal_port) / Raw(encrypted_data)
                self._id += 1
                send(fragment(packet, fragsize=1400))
                data = data[crop_len:]
            else:
                encrypted_data = self.full_encrypt(code_prefix + data)
                packet = IP(dst=tb.addresses[1][0], id=self._id) / TCP(dport=tb.addresses[1][1], sport=self.personal_port) / Raw(encrypted_data)
                self._id += 1
                send(fragment(packet, fragsize=1400))
                break

    def full_encrypt(self, data):
        encrypted_data = self.layer3.encrypt(data, self.session_id, tb.addresses[4][0], str(tb.addresses[4][1]))
        encrypted_data = self.layer2.encrypt(encrypted_data, self.session_id, tb.addresses[3][0], str(tb.addresses[3][1]))
        encrypted_data = self.layer1.encrypt(encrypted_data, self.session_id, tb.addresses[2][0], str(tb.addresses[2][1]))
        return encrypted_data

    def decrypt_packet(self, data):
        decrypted_data = self.layer0.b_decrypt(data)
        decrypted_data = self.layer0.b_decrypt(decrypted_data[1])
        decrypted_data = self.layer0.b_decrypt(decrypted_data[1])
        return decrypted_data


if __name__ == '__main__':
    """if len(sys.argv) > 1:
        personal_port = int(sys.argv[1])
        test_send_data = bytes(sys.argv[2].encode("utf-8"))
        self.ports[3] = int(sys.argv[3])"""
    print("client started")
    c = Client()
    c.sniffer()
