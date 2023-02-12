import socket

# Create a socket for the server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to a specific address and port
server_address = ("10.0.0.24", 55559)
server_socket.bind(server_address)

# Listen for incoming connections
server_socket.listen(1)
print("Server is listening on", server_address)

# Accept incoming connections
connection, client_address = server_socket.accept()
print("Accepted connection from", client_address)

# Receive and send back data from the client
while True:
    data = connection.recv(1024)
    if not data:
        break
    print("Got data:", data)
    connection.sendall(data)

# Close the connection
connection.close()
server_socket.close()
