import socket

# default values
loopback_interface = "Software Loopback Interface 1"
main_interface = "Intel(R) Ethernet Connection (7) I219-V"
server_ip = "10.0.0.24"


def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')


def int_from_bytes(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, 'big')


def stringify(lst):
    lst = map(str, lst)
    string = "['"+"', '".join(lst)+"']"
    return string


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
