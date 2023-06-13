import pickle
import socket
import sys
from threading import Thread
import time
from queue import Queue, Empty
import atexit

from tools.layer import Layer
from tools.bidict import BiDict
import tools.toolbox as tb


# CLIENT KEY - temporary
layer0 = Layer()
# layer0.change_keys("0", False)

node_layer = Layer()
key_dir = ""

finished = False
sockA_to_sockB = BiDict()
sock_to_layer = {}
ip = None


def find_my_ip():
    global ip
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))
    nat_ip_address = s.getsockname()[0]
    s.close()
    ip = nat_ip_address


def disconnect(HOST, PORT):
    global ip

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.bind((ip, personal_port))
    client_socket.connect((HOST, PORT))

    message = b"N" + pickle.dumps((ip, personal_port, "DISCONNECTING"))

    client_socket.send(message)
    response = client_socket.recv(1024).decode('utf-8')

    if response == "OK":
        print("Disconnected")
    else:
        print("Disconnect unsuccessful")

    client_socket.close()


def boot(HOST, PORT):
    """
    Makes a connection with the directory server
    :param HOST: directory server ip
    :param PORT: directory server port
    :return:
    """
    find_my_ip()

    node_layer.store_keys(key_dir)
    with open(key_dir+"public_key.pem", "r") as k:
        pk = k.read()

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.bind((ip, personal_port))
    client_socket.connect((HOST, PORT))

    message = b"N" + pickle.dumps((ip, personal_port, "CONNECTING", pk))

    client_socket.send(message)
    response = client_socket.recv(1024).decode('utf-8')

    print(response)
    if response != "OK" and response != "REACTIVATED":
        input()

    client_socket.close()


def packet_handle():
    """
    starts node and allows new connections
    :return:
    """
    global ip

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_address = (ip, personal_port)
    server_socket.bind(server_address)

    server_socket.listen(5)
    print("Server is listening on", server_address)

    while True:
        client_socket, client_address = server_socket.accept()

        # Create a thread to handle the client
        client_thread = Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()


def handle_client(client_socket, client_address, mode="CTS"):
    if mode == "CTS":
        print("Connected:", client_address)

    while True:
        data = recv_all(client_socket)
        if not data[1]:
            break
        data = data[0]
        if not data:
            break
        process_data(data, client_socket, client_address, mode)

    if mode == "CTS":
        print("Disconnected:", client_address)
        stc_sock = sockA_to_sockB.get_value(client_socket)
        sockA_to_sockB.del_item(client_socket, stc_sock)
        try:
            stc_sock.close()
        except Exception as e:
            print(e)

    client_socket.close()


def process_data(data, client_socket, client_address, mode):
    global sockA_to_sockB

    if mode == "CTS":
        if not sockA_to_sockB.has_this_key(client_socket):  # If this is the first message then add it to the dict
            data = node_layer.startup_decrypt(data)
            _ip, _port, data = data
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((_ip, _port))
            sockA_to_sockB.add(client_socket, sock)

            client_thread = Thread(target=handle_client, args=(sock, sock.getsockname(), "STC"))
            client_thread.start()

            set_up_route(data, sock, client_address)
            print(f"{key_num}-->{_ip}:{_port}")
            return

        data = node_layer.decrypt(data)
        peername = sockA_to_sockB.get_value(client_socket).getpeername()
        _ip, _port = peername

        print(f"{key_num}-->{_ip}:{_port}")
        send_data(data, sockA_to_sockB.get_value(client_socket))
    elif mode == "STC":
        if not sockA_to_sockB.has_this_value(client_socket):
            print("???")
            exit()

        sock = sockA_to_sockB.get_key(client_socket)
        _ip, _port = sock.getpeername()
        print(f"{_ip}:{_port}<--{key_num}")
        data = encrypt_packet(data, client_socket)
        send_data(data, sock)


def set_up_route(data, sock, src_address):
    global sock_to_layer
    pk = data[:451]
    data = data[451:]

    with open(key_dir+f"public_key{src_address}".replace(".", "_") + ".pem", "wb") as k:
        k.write(pk)

    l = Layer()
    l.change_keys(key_dir, f"{src_address}".replace(".", "_"), False)
    sock_to_layer[sock] = l

    send_data(data, sock)


def encrypt_packet(data, cs):
    global sock_to_layer
    layer = sock_to_layer[cs]
    encrypted_data = layer.b_encrypt(data)
    return encrypted_data


def send_data(data, sock):
    sock.sendall(str(len(data)).zfill(10).encode() + data)


def recv_all(sock):
    """
    function that receive data from socket by the wanted format
    :param sock: socket
    :return: tuple - (msg/error - str, status(True for ok, False for error))
    """
    try:
        msg_size = sock.recv(10)
    except:
        return "recv error1", False
    if not msg_size:
        return "msg length error1", False
    try:
        msg_size = int(msg_size)
    except:  # not an integer
        return "msg length error2", False

    msg = b''
    # this is a fail - safe -> if the recv not giving the msg in one time
    while len(msg) < msg_size:
        try:
            msg_fragment = sock.recv(msg_size - len(msg))
        except:
            return "recv error", False
        if not msg_fragment:
            return "msg data is none", False
        msg = msg + msg_fragment

    return msg, True


if __name__ == '__main__':
    if len(sys.argv) > 1:
        personal_port = int(sys.argv[1])
        start_port = int(sys.argv[2])
        key_num = sys.argv[3]
        key_dir = f"keys/keys{key_num}/"
        # node_layer.change_keys(key_num, True)

    ds_ip = "10.0.0.24"
    # atexit.register(lambda: disconnect(ds_ip, 55677))  # Not working currently
    boot(ds_ip, 55677)
    packet_handle()
