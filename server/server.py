import os
import pickle
from threading import Thread
import time
from queue import Queue, Empty
import secrets
import sys
import socket
import string

import tools.toolbox as tb
from tools.layer import Layer
from database.database import Database


data = b""
"""
layer1 = Layer()
layer1.change_keys("1")
layer2 = Layer()
layer2.change_keys("2")
"""

finished = False
sessions = {}
conversations = {}
personal_port = 55559
ip = None

layer0 = Layer()
server_layer = Layer()
key_dir = "keys/"


def find_my_ip():
    global ip
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))
    nat_ip_address = s.getsockname()[0]
    s.close()
    ip = nat_ip_address


def boot(HOST, PORT):
    global ip

    find_my_ip()

    server_layer.store_keys(key_dir)
    with open(key_dir+"public_key.pem", "r") as k:
        pk = k.read()

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.bind((ip, personal_port))
    client_socket.connect((HOST, PORT))

    message = b"S" + pickle.dumps((ip, personal_port, "CONNECTING", pk))

    client_socket.send(message)
    response = client_socket.recv(1024).decode('utf-8')

    print(response)
    if response != "OK" and response != "REACTIVATED":
        input()

    client_socket.close()


def packet_handle():
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


def handle_client(client_socket, client_address):
    print("Connected:", client_address)
    db = Database()

    while True:
        data = recv_all(client_socket)
        if not data[1]:
            break
        data = data[0]
        if not data:
            break
        process_data(data, client_socket, client_address, db)

    client_socket.close()
    if client_socket in sessions:
        del sessions[client_socket]
    print("Disconnected:", client_address)


def process_data(data, client_socket, client_address, db):
    global conversations

    key = str(client_address)
    data = decrypt_packet(data)

    code = data[:1]

    if code == b"I":
        signin(key, data[1:], client_socket, db)
        return
    if code == b"S":
        signup(key, data[1:], client_socket, db)
        return
    if code == b"B":
        save_pk(key, data[1:])
        reply(b"Started", b'\xf2\xee\x07', key, client_socket)
        return

    if client_socket not in sessions:
        reply(b"Not signed-in", b'\xf2\xee\x07', key, client_socket)
        return

    if code == b"U":
        if client_socket in conversations:
            upload_request(key, data[1:], client_socket)
        else:
            file_name = data[1:]
            conversations[client_socket] = file_name
            # blue v for accepting
            reply(b"Request accepted", b'\xf2\xee\x07', key, client_socket)
        return
    if code == b"D":
        file_names = data[1:]
        download(key, file_names, client_socket)
        return
    if code == b"L":
        send_list(key, client_socket)
        return


def save_pk(key, pk):
    with open(key_dir+f"public_key[{key}]".replace(".", "_") + ".pem", "wb") as k:
        k.write(pk)


def signin(key, user, cs, db):
    h, auth = pickle.loads(user)
    if not db.check_user_exists(h):
        reply(b"Hash incorrect", b'\xd3\xb6\xad', key, cs)
        return
    if not db.check_user_otp(h, auth):
        reply(b"Auth incorrect", b'\xd3\xb6\xad', key, cs)
        return
    reply(b"sign in successful", b'\xc6\xbd\x06', key, cs)
    sessions[cs] = db.get_user_by_hash(h)[0]


def signup(key, user, cs, db):
    alphabet = string.ascii_letters + string.digits
    random_hash = ''.join(secrets.choice(alphabet) for _ in range(10))

    result = db.add_user(random_hash)
    print(result)
    print(db.get_all_users())
    if result:
        sessions[cs] = db.get_user_by_hash(random_hash)[0]
        os.mkdir(f"server_files/f{sessions[cs]}")
        reply(pickle.dumps((random_hash, result)), b'\x9d\xf6\x9e', key, cs)
    else:
        reply(b"User already exists", b'\xd3\xb6\xad', key, cs)


def send_list(key, cs):
    user_folder = sessions[cs]
    entries = os.scandir(f"server_files/f{user_folder}")
    entry_list = list_from_iter(entries)
    if "Thumbs.db" in entry_list:
        entry_list.remove("Thumbs.db")
    reply(str(entry_list).encode('utf-8'), b'\x98\x16\xac', key, cs)


def download(key, file_names, cs):
    user_folder = sessions[cs]
    file_names = eval(file_names)

    # blue v for accepting
    reply(b"Request accepted", b'\xf2\xee\x07', key, cs)

    for file in file_names:
        with open(f"server_files/f{user_folder}/{file}", "rb") as f:
            data = f.read()
            print(len(data))
            reply(file.encode(), b'\xa7\x98\xa8', key, cs)
            reply(data, b'\xa7\x98\xa8', key, cs)


def upload_request(key, load, cs):
    global conversations

    upload(load, conversations[cs], key, cs)
    del conversations[cs]


def upload(data, file_name, key, cs):
    user_folder = sessions[cs]
    with open(f"server_files/f{user_folder}/{file_name.decode()}", "wb") as i:
        i.write(data)
        time.sleep(0.001)
    reply(b'upload complete', b'\x9d\xb7\xe3', key, cs)


def reply(data, code_prefix, key, sock):
    """
    Sends back replies on received messages to imitate a server
    :param code_prefix: to let other side know meaning of aproach
    :param key: consists of src#sport or received packet
    :param data: The data that is to be replied
    :param sock: client socket
    :return:
    """
    sendable_data = encrypt_packet(code_prefix + data, key)
    sock.sendall(str(len(sendable_data)).zfill(10).encode() + sendable_data)


def list_from_iter(iter):
    l = []
    for i in iter:
        l.append(i.name)
    return l


def decrypt_packet(data):
    decrypted_data = server_layer.decrypt(data)
    return decrypted_data


def encrypt_packet(data, key):
    layer0.change_keys(key_dir, f"[{key}]".replace(".", "_"), False)
    encrypted_data = layer0.b_encrypt(data)
    return encrypted_data


def recv_all(sock):
    """
    function that receive data from socket by the wanted format
    :param sock: socket
    :return: tuple - (msg/error - str, status(True for ok, False for error))
    """
    try:
        msg_size = sock.recv(10)
    except:
        return "recv error", False
    if not msg_size:
        return "msg length error", False
    try:
        msg_size = int(msg_size)
    except:  # not an integer
        return "msg length error", False

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

boot("10.0.0.24", 55677)
packet_handle()
