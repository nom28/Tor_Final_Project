# from scapy.all import *
# from scapy.layers.inet import *
from tools.formlayer import FormLayer

"""
packet = IP()/TCP(sport=57575, dport=55555)/Raw(load="hello")

sr1(IP(dst="127.0.0.1")/ICMP())

print(IFACES.show(True))
packet.show()
send(packet)

"""
x = FormLayer()

encrypted_data = x.encrypt("hola mr pablo")

print(encrypted_data)
print("\n--------------------------------\n")
data = x.decrypt(encrypted_data)

print(data)
print(data.decode("utf-8"))
