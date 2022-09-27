from scapy.all import *

conf.L3socket = L3RawSocket

capture = sniff(filter='dst port 55555', count=1)
print("done sniffing")
capture.summary()
