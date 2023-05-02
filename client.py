import warnings
from cryptography.utils import CryptographyDeprecationWarning
from queue import *

from tools.layer_new import Layer
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
    ports = [55556, 55557, 55558, 55559]
    ip = "127.0.0.1"
    personal_port = 55555
    finished = False

    test_send_data = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-="*300

    def __init__(self):
        self.layer0.change_keys("0")
        self.layer1.change_keys("1")
        self.layer2.change_keys("2")
        self.layer3.change_keys("3")

    def sniffer(self, q):
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
                    if TCP not in pkt:
                        continue
                    if pkt[TCP].ack == 1:
                        continue
                    # pkt.show()
                    data = self.decrypt_packet(pkt.load)
                    q.put(data[1])  # [0] is session key
                except AttributeError:
                    raise
            else:
                # do not really understand why this is needed, but does not print all packets if not.
                time.sleep(0.001)

    def sniff_loopback(self):
        sniff(prn=lambda x: self.q.put(x), filter=f"dst port {self.personal_port}", iface="\\Device\\NPF_Loopback")

    def send(self, data, code_prefix):
        encrypted_data = self.full_encrypt(code_prefix + tb.int_to_bytes(len(data)))
        packet = IP(dst=self.ip) / TCP(dport=self.ports[0], sport=self.personal_port) / Raw(encrypted_data)
        send(packet)
        while len(data) > 0:
            # time.sleep(0.1)
            if len(data) > 16384:
                encrypted_data = self.full_encrypt(code_prefix + data[:16384])
                packet = IP(dst=self.ip) / TCP(dport=self.ports[0], sport=self.personal_port) / Raw(encrypted_data)
                send(packet)
                data = data[16384:]
            else:
                encrypted_data = self.full_encrypt(code_prefix + data)
                packet = IP(dst=self.ip) / TCP(dport=self.ports[0], sport=self.personal_port) / Raw(encrypted_data)
                send(packet)
                break

    def full_encrypt(self, data):
        encrypted_data = self.layer3.encrypt(data, self.session_id, self.ip, str(self.ports[3]))
        encrypted_data = self.layer2.encrypt(encrypted_data, self.session_id, self.ip, str(self.ports[2]))
        encrypted_data = self.layer1.encrypt(encrypted_data, self.session_id, self.ip, str(self.ports[1]))
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
