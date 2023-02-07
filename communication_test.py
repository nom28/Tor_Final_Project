from scapy.all import *
from scapy.layers.inet import *
from queue import *

src_ip = "127.0.0.1"
dst_ip = "10.100.102.105"
dst_port = 55559
personal_port = 55554
finished = False


def sniff_loopback(q):
    sniff(prn=lambda x: q.put(x), filter=f"dst port {personal_port}", iface="\\Device\\NPF_Loopback")


def send_data(data):
    packet = IP(dst=dst_ip) / TCP(dport=dst_port, sport=personal_port) / Raw(data)
    send(packet)


def send_data_unregistered_port(data):
    packet = IP(dst=dst_ip) / TCP(dport=dst_port, sport=55553) / Raw(data)
    send(packet)


def _sender():
    time.sleep(1)
    send_data(b"this is the first test")
    time.sleep(2)
    send_data(b"this is the second test")
    send_data_unregistered_port(b"third")
    send_data_unregistered_port(b"and forth")
    send_data(b"fifth:)")


def threaded_sniff():
    q = Queue()
    print("initiating sniffer")
    sniffer = Thread(target=sniff_loopback, args=(q,))
    sniffer.daemon = True
    sniffer.start()
    time.sleep(1)  # just to make sure the sniffer doesn't override with future scapy functions.
    print("sniffer initiated - listening\n")
    print("sender initiating")
    sender = Thread(target=_sender)
    sender.daemon = True
    sender.start()
    print("sender initiated")

    while not finished:
        if not q.empty():
            try:
                pkt = q.get()
                if TCP not in pkt:
                    continue
                if pkt[TCP].ack == 1:
                    print("ack")
                    continue
                # pkt.show()
                data = pkt.load
                print(data)
                print("---------")
                time.sleep(0.00001)
            except AttributeError:
                raise
        else:
            # do not really understand why this is needed, but does not print all packets if not.
            time.sleep(0.00001)


if __name__ == '__main__':
    if len(sys.argv) > 1:
        personal_port = int(sys.argv[1])
    print("client started")
    threaded_sniff()