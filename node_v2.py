"""
This file is a work in progress and might not be used.
this is a node code but with sockets and without scapy.
"""


import warnings
from cryptography.utils import CryptographyDeprecationWarning
from threading import Thread
import time
from queue import Queue, Empty
import socket
import threading
import logging

from tools.layer_new import Layer

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
from scapy.all import *
from scapy.layers.inet import *

logging.basicConfig(level=logging.DEBUG)

# CLIENT KEY - temporary
layer0 = Layer()
layer0.change_keys("0")

node_layer = Layer()
# keys are added on the bottom

finished = False

sk_to_dst = {}
src_to_sk = {}

client_sockets = []
server_sockets = {}

# Create a socket object
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to a specific address and port
s.bind(("localhost", 12345))

# Listen is in the bottom

q_forwards = Queue()
q_backwards = Queue()


def handle_conn():
    # Listen for incoming connections
    s.listen(5)

    while True:
        # Accept a connection
        c, addr = s.accept()
        logging.debug("> Got connection from", addr)
        client_sockets.append(c)

        # Start a new thread to handle the client
        client_handler = threading.Thread(
            target=handle_client,
            args=(c,)  # without comma, you'll get a TypeError
        )
        client_handler.daemon = True
        client_handler.start()


def handle_traffic():
    while True:
        if not q_forwards.empty():
            data, addr, session_id = q_forwards.get(timeout=1)
            send_data(data, addr[0], addr[1])


def handle_client(client_socket):
    """
        Function to handle a single client's requests
    """
    while True:
        try:
            msg_size = client_socket.recv(8)
            if not msg_size:
                client_sockets.remove(client_socket)
                client_socket.close()
                break
        except:
            logging.error("recv error")
        if not msg_size:
            logging.error("msg length error")
        try:
            msg_size = int(msg_size)
        except:  # not an integer
            logging.error("msg length error")

        msg = b''
        # this is a fail-safe -> if the recv not giving the msg in one time
        while len(msg) < msg_size:
            try:
                msg_fragment = client_socket.recv(msg_size - len(msg))
                if not msg_fragment:
                    client_sockets.remove(client_socket)
                    client_socket.close()
                    break
            except:
                logging.error("recv error")
            if not msg_fragment:
                logging.error("msg data is none")
            msg = msg + msg_fragment

        # msg is fully built.
        # msg = msg.decode(errors="ignore")
        pkt = decrypt_packet(msg)
        ip, port, session_id, data = pkt

        q_forwards.put((data, (ip, port), session_id))



"""
try:
                    # print(f"sending data to client number {self.__client_ids[client]}")
                    client.send(str(len(data.encode())).zfill(
                        8).encode() + data.encode())
                except:
                    print("error")
                    # pass
"""


"""
def threaded_sniff_with_send():
    q = Queue()
    logging.debug("initiating sniffer")
    sniffer = Thread(target=sniff_loopback, args=(q,))
    sniffer.daemon = True
    sniffer.start()
    time.sleep(1)  # just to make sure the sniffer doesn't override with future scapy functions.
    logging.debug("sniffer initiated - listening")

    while not finished:
        if not q.empty():
            try:
                pkt = q.get(timeout=1)
                if TCP not in pkt:
                    continue
                if pkt[TCP].ack == 1:
                    logging.debug("ack")
                    continue
                # pkt.show()
                src = pkt[IP].src
                sport = pkt[TCP].sport
                pkt_address = stringify([src, sport])
                logging.debug(pkt_address)

                if pkt_address in sk_to_dst.values() or pkt_address not in src_to_sk:
                    pkt = decrypt_packet(pkt.load)
                    ip, port, session_id, data = pkt

                    if session_id not in src_to_sk.values():
                        src_to_sk[stringify([ip, port])] = session_id
                    if session_id not in sk_to_dst:
                        sk_to_dst[session_id] = pkt_address

                    send_data(data, ip, port)
                    logging.debug(f"{key_num}-->")
                else:
                    if pkt_address not in src_to_sk:
                        logging.error("very interesting")
                        exit()
                    session_id = src_to_sk[pkt_address]
                    address = eval(sk_to_dst[session_id])
                    data = encrypt_packet(pkt.load)
                    send_data(data, address[0], int(address[1]))
                    logging.debug(f"{address}<--{key_num}")
            except AttributeError:
                pass


# "Software Loopback Interface 1"
def sniff_loopback(q):
    sniff(prn=lambda x: q.put(x), filter=f"dst port {personal_port}", iface="\\Device\\NPF_Loopback")
"""

def decrypt_packet(data):
    decrypted_data = node_layer.decrypt(data)
    return decrypted_data


def encrypt_packet(data):
    encrypted_data = layer0.b_encrypt(data)
    return encrypted_data


def send_data(data, ip, port):
    if (ip, port) not in server_sockets:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        s.send(data)
        server_sockets[(ip, port)] = s
        return

    s = server_sockets[(ip, port)]
    s.send(data)


def stringify(lst):
    lst = map(str, lst)
    string = "['"+"', '".join(lst)+"']"
    return string


if __name__ == '__main__':
    if len(sys.argv) > 1:
        personal_port = int(sys.argv[1])
        key_num = sys.argv[2]

        node_layer.change_keys(key_num)

    connection_handler = threading.Thread(
        target=handle_conn
    )
    connection_handler.daemon = True
    connection_handler.start()



    # threaded_sniff_with_send()
