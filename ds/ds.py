import socket
import threading
import pickle
import random

from database.database import Database
from database.server_database import ServerDatabase


class Ds:
    def __init__(self, host, port):
        self.db = Database()
        self.sdb = ServerDatabase()
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.clients = []

    def broadcast(self, message):
        for client in self.clients:
            client.send(message)

    def handle_client(self, client_socket, client_address):
        self.clients.append(client_socket)
        message = client_socket.recv(1024)
        if not message:
            client_socket.close()
            self.clients.remove(client_socket)
            return

        request = pickle.loads(message[1:])
        ip = request[0]
        port = request[1]
        if ip != client_address[0] or port != client_address[1]:
            print("> Intruder detected:", client_address)
            client_socket.send(b"WRONG_ADDR")
            client_socket.close()
            self.clients.remove(client_socket)
            return

        if message[:1] == b"N":
            self.node_request(request, client_socket, client_address)
        elif message[:1] == b"C":
            self.client_request(request, client_socket, client_address)
        elif message[:1] == b"S":
            self.server_request(request, client_socket, client_address)
        client_socket.close()
        self.clients.remove(client_socket)

    def node_request(self, request, client_socket, client_address):
        ip = request[0]
        port = request[1]
        state = request[2]
        if state == "DISCONNECTING":
            self.db.deactivate_node(ip, port)
            print("> Node disconnected:", client_address)
            client_socket.send(b"OK")

        if state == "CONNECTING":
            public_key = request[3]
            r = self.db.add_node(ip, port, public_key, 1)
            if r:
                print("> Node connected:", client_address)
                client_socket.send(b"OK")
            else:
                print("> Node reconnected:", client_address)
                client_socket.send(b"REACTIVATED")
        if state == "DISCONTINUING":
            self.db.remove_node(ip, port)
            print("> Node removed:", client_address)
            client_socket.send(b"OK")

    def server_request(self, request, client_socket, client_address):
        ip = request[0]
        port = request[1]
        state = request[2]
        if state == "DISCONNECTING":
            self.sdb.deactivate_server(ip, port)
            print("> Server disconnected:", client_address)
            client_socket.send(b"OK")

        if state == "CONNECTING":
            public_key = request[3]
            r = self.sdb.add_server(ip, port, public_key, 1)
            if r:
                print("> Server connected:", client_address)
                client_socket.send(b"OK")
            else:
                print("> Server reconnected:", client_address)
                client_socket.send(b"REACTIVATED")
        if state == "DISCONTINUING":
            self.sdb.remove_server(ip, port)
            print("> Server removed:", client_address)
            client_socket.send(b"OK")

    def client_request(self, request, client_socket, client_address):
        state = request[2]
        server_addr = request[3]
        if state == "CONNECTING":
            if not self.sdb.check_server_exists(server_addr[0], server_addr[1]):
                client_socket.send(b"ERROR2")
                print("server does not exist")
                return
            server = self.sdb.get_server(server_addr[0], server_addr[1])

            nodes = self.db.get_all_nodes(1)
            if len(nodes) < 3:
                client_socket.send(b"ERROR3")
                print("Not enough nodes")
                return
            chosen_nodes = random.sample(nodes, 3)

            reply = pickle.dumps(((chosen_nodes[0][1], chosen_nodes[0][2], chosen_nodes[0][3]),
                                  (chosen_nodes[1][1], chosen_nodes[1][2], chosen_nodes[1][3]),
                                  (chosen_nodes[2][1], chosen_nodes[2][2], chosen_nodes[2][3]),
                                  server[3]))
            client_socket.send(reply)
            print("> Client connected:", client_address)
        elif state == "RECONNECTING":
            # Future feature
            pass

    def run(self):
        print(f"Server started on {self.host}:{self.port}")
        while True:
            client_socket, client_address = self.server_socket.accept()
            self.handle_client(client_socket, client_address)


if __name__ == '__main__':
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))
    nat_ip_address = s.getsockname()[0]
    s.close()

    directory_server = Ds(nat_ip_address, 55677)
    directory_server.run()
