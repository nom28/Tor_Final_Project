# from scapy.all import *
# from scapy.layers.inet import *
from tools.layer import Layer

"""
packet = IP()/TCP(sport=57575, dport=55555)/Raw(load="hello")

sr1(IP(dst="127.0.0.1")/ICMP())

print(IFACES.show(True))
packet.show()
send(packet)

"""
layer1 = Layer()
layer2 = Layer()
layer3 = Layer()

encrypted_data = layer1.encrypt(layer2.encrypt(layer3.encrypt(bytes("hello mr pablo", 'utf-8'))))

print(encrypted_data)
print("\n--------------------------------\n")

decrypted_data = layer3.decrypt(layer2.decrypt(layer1.decrypt(encrypted_data)))

print(decrypted_data)
print(decrypted_data.decode("utf-8"))
