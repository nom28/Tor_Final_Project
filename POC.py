from scapy.all import *
from scapy.layers.inet import *
from tools.layer_new import Layer
import time
layer1 = Layer()
layer1.change_keys("1")
layer2 = Layer()
layer2.change_keys("2")
layer3 = Layer()
layer3.change_keys("3")

session_id = random.randbytes(20)
ports = (55556, 55557, 55558, 55559)
ip = "127.0.0.1"


def send_data(data):
    while len(data) > 0:
        print(len(data))
        # time.sleep(0.1)
        if len(data) > 16384:
            encrypted_data = full_encrypt(data[:16384])
            packet = IP(dst="127.0.0.1") / TCP(dport=ports[0], sport=55555) / Raw(encrypted_data)
            print(packet.load)
            send(packet)
            data = data[16384:]
        else:
            encrypted_data = full_encrypt(data)
            packet = IP(dst="127.0.0.1") / TCP(dport=ports[0], sport=55555) / Raw(encrypted_data)
            send(packet)
            # ending argument
            break

    done_argument = full_encrypt(b"DONE")
    packet = IP(dst="127.0.0.1") / TCP(dport=ports[0], sport=55555) / Raw(done_argument)
    send(packet)


def full_encrypt(data):
    encrypted_data = layer3.encrypt(data, session_id, ip, str(ports[3]))
    encrypted_data = layer2.encrypt(encrypted_data, session_id, ip, str(ports[2]))
    encrypted_data = layer1.encrypt(encrypted_data, session_id, ip, str(ports[1]))
    return encrypted_data

if __name__ == '__main__':
    send_data(b"hello")

    """
    with open("1mbFlower.jpg", "rb") as d:
        data_pre = d.read()
        send_data(data_pre)
    """

"""
encrypted_data = layer1.encrypt(layer2.encrypt(layer3.encrypt(bytes(x, 'utf-8'))))

print(encrypted_data)
print("\n--------------------------------\n")

decrypted_data = layer3.decrypt(layer2.decrypt(layer1.decrypt(encrypted_data)))

print(decrypted_data)
print(decrypted_data.decode("utf-8"))


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(decrypted_data)
    data = s.recv(1024)

print(f"Received {data!r}")
"""
