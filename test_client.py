import socket

# Create a socket for the client
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

client_socket.bind(("10.0.0.24", 55554))

# Connect the socket to the server
server_address = ("10.0.0.24", 55559)
client_socket.connect(server_address)

# Loop to allow the user to input data to be sent to the server
while True:
    message = input("Enter message to send to server (type 'quit' to exit): ").encode()
    if message.decode().strip().lower() == "quit":
        break
    client_socket.sendall(message)
    data = client_socket.recv(1024)
    print("Received from server:", data.decode())

# Close the connection
client_socket.close()
