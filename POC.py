from scapy.all import *
from scapy.layers.inet import *
from tools.layer import Layer
import time
layer1 = Layer()
layer1.change_keys("1")
layer2 = Layer()
layer2.change_keys("2")
layer3 = Layer()
layer3.change_keys("3")


def send_data(data):
    while len(data) > 0:
        print(len(data))
        time.sleep(0.1)
        if len(data) > 16384:
            encrypted_data = layer1.encrypt(layer2.encrypt(layer3.encrypt(data[:16384])))
            packet = IP(dst="127.0.0.1") / TCP(dport=55656, sport=55555) / Raw(encrypted_data)
            send(packet)
            data = data[16384:]
        else:
            encrypted_data = layer1.encrypt(layer2.encrypt(layer3.encrypt(data)))
            packet = IP(dst="127.0.0.1") / TCP(dport=55656, sport=55555) / Raw(encrypted_data)
            send(packet)
            # ending argument
            break

    done_argument = layer1.encrypt(layer2.encrypt(layer3.encrypt(b"DONE")))
    packet = IP(dst="127.0.0.1") / TCP(dport=55656, sport=55555) / Raw(done_argument)
    send(packet)


with open("1mbFlower.jpg", "rb") as d:
    data_pre = d.read()
    send_data(data_pre)

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
