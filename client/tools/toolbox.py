import socket

# default values
loopback_interface = "Software Loopback Interface 1"
main_interface = "Intel(R) Wi-Fi 6 AX201 160MHz"
node_ip = "172.16.67.125"
loopback_ip = "127.0.0.1"
# addresses: class testing
# adresses = (("172.16.163.53", 55555), (node_ip, 55556), (node_ip, 55557), (node_ip, 55558), ("172.16.67.122", 555559))
# addresses: home testing
adresses = ((loopback_ip, 55555), (loopback_ip, 55556), (loopback_ip, 55557), (loopback_ip, 55558), (loopback_ip, 55559))


def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')


def int_from_bytes(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, 'big')


def find_next_available_port(start_port):
    for port in range(start_port, 65535):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(('0.0.0.0', port))
            sock.close()
            return port
        except:
            continue
