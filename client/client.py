from queue import *
import pickle
import socket
from threading import Thread

from tools.layer import Layer
import tools.toolbox as tb


class Client:
    layer0 = Layer()
    layer1 = Layer()
    layer2 = Layer()
    layer3 = Layer()
    layerS = Layer()
    q = Queue()
    ready_q = Queue()

    main_socket = None

    ip = None
    personal_port = 55555
    finished = False
    addresses = None

    def __init__(self):
        self.layer0.store_keys("0")
        self.find_my_ip()
        ds_ip = "10.0.0.24"
        self.boot(ds_ip, 55677)

    def find_my_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        nat_ip_address = s.getsockname()[0]
        s.close()
        self.ip = nat_ip_address

    def boot(self, HOST, PORT):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.bind((self.ip, self.personal_port))
        client_socket.connect((HOST, PORT))

        message = b"C" + pickle.dumps((self.ip, self.personal_port, "CONNECTING", (tb.server_ip, 55559)))

        client_socket.send(message)
        response = client_socket.recv(2048)

        if response == b"ERROR2":
            print(response)
            client_socket.close()
            exit()

        response = pickle.loads(response)
        self.addresses = ((self.ip, 55555),
                          (response[0][0], response[0][1]),
                          (response[1][0], response[1][1]),
                          (response[2][0], response[2][1]),
                          (tb.server_ip, 55559),)

        print(self.addresses)

        with open('keys\\public_key1.pem', 'wb') as f:
            f.write(response[0][2].encode('utf-8'))
        with open('keys\\public_key2.pem', 'wb') as f:
            f.write(response[1][2].encode('utf-8'))
        with open('keys\\public_key3.pem', 'wb') as f:
            f.write(response[2][2].encode('utf-8'))
        with open('keys\\public_keyS.pem', 'wb') as f:
            f.write(response[3].encode('utf-8'))

        self.layer1.change_keys("1", False)
        self.layer2.change_keys("2", False)
        self.layer3.change_keys("3", False)
        self.layerS.change_keys("S", False)

        client_socket.close()

        self.set_up_route()

    def set_up_route(self):
        self.sniffer()

        with open("keys/public_key0.pem", "rb") as pk:
            data = pk.read()

        # This is now done in a dumb way since server does not encrypt YET
        encrypted_data = self.layerS.encrypt(b'B'+data)
        encrypted_data = self.layer3.startup_encrypt(data+encrypted_data, self.addresses[4][0], str(self.addresses[4][1]))
        encrypted_data = self.layer2.startup_encrypt(data+encrypted_data, self.addresses[3][0], str(self.addresses[3][1]))
        encrypted_data = self.layer1.startup_encrypt(data+encrypted_data, self.addresses[2][0], str(self.addresses[2][1]))

        self.main_socket.sendall(str(len(encrypted_data)).zfill(10).encode() + encrypted_data)

    def sniffer(self):
        self.main_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.main_socket.connect(self.addresses[1])

        print("initiating sniffer")
        sniffer = Thread(target=self.receive_messages)
        sniffer.daemon = True
        sniffer.start()
        print("sniffer initiated - listening")

    def receive_messages(self):
        while True:
            try:
                data = self.recv_all()
                if data[1]:
                    data = self.decrypt_packet(data[0])
                    self.ready_q.put(data)
            except socket.error as e:
                print("Socket error:", e)
                break

    def send(self, data, code_prefix):
        data = code_prefix + data
        encrypted_data = self.full_encrypt(data)
        print(str(len(encrypted_data)).zfill(10).encode())
        print(encrypted_data)
        self.main_socket.sendall(str(len(encrypted_data)).zfill(10).encode() + encrypted_data)

    def full_encrypt(self, data):
        encrypted_data = self.layerS.encrypt(data)
        encrypted_data = self.layer3.encrypt(encrypted_data)
        encrypted_data = self.layer2.encrypt(encrypted_data)
        encrypted_data = self.layer1.encrypt(encrypted_data)
        return encrypted_data

    def decrypt_packet(self, data):
        decrypted_data = self.layer0.b_decrypt(data)
        decrypted_data = self.layer0.b_decrypt(decrypted_data)
        decrypted_data = self.layer0.b_decrypt(decrypted_data)
        decrypted_data = self.layer0.b_decrypt(decrypted_data)
        return decrypted_data

    def recv_all(self):
        try:
            msg_size = self.main_socket.recv(10)
        except:
            return "recv error", False
        if not msg_size:
            return "msg length error", False
        try:
            msg_size = int(msg_size)
            print(msg_size)
        except:  # not an integer
            return "msg length error", False

        msg = b''
        # this is a fail - safe -> if the recv not giving the msg in one time
        while len(msg) < msg_size:
            try:
                msg_fragment = self.main_socket.recv(msg_size - len(msg))
            except:
                return "recv error", False
            if not msg_fragment:
                return "msg data is none", False
            msg = msg + msg_fragment
        print(len(msg))
        return msg, True


if __name__ == '__main__':
    """if len(sys.argv) > 1:
        personal_port = int(sys.argv[1])
        test_send_data = bytes(sys.argv[2].encode("utf-8"))
        self.ports[3] = int(sys.argv[3])"""
    print("client started")
    c = Client()
