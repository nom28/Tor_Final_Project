import pydivert
import random
import sys

from tools.layer_new import Layer

MODE = "ONE"  # "ONE" OR "THREE"

layer0 = Layer()
layer0.change_keys("0")

layer1 = Layer()
layer1.change_keys("1")
layer2 = Layer()
layer2.change_keys("2")
layer3 = Layer()
layer3.change_keys("3")

session_id = random.randbytes(20)
nodes = (("10.0.0.24", 55556), ("10.0.0.24", 55557), ("10.0.0.24", 55558))
# ip = "10.0.0.24"
personal_port = 55555
finished = False


def encrypt_packet(data, dst_ip, dst_port):
    if MODE == "THREE":
        encrypted_data = layer3.encrypt(data, session_id, dst_ip, str(dst_port))
        encrypted_data = layer2.encrypt(encrypted_data, session_id, nodes[2][0], str(nodes[2][1]))
        encrypted_data = layer1.encrypt(encrypted_data, session_id, nodes[1][0], str(nodes[1][1]))
    elif MODE == "ONE":
        encrypted_data = layer1.encrypt(data, session_id, dst_ip, str(dst_port))
    return encrypted_data


def decrypt_packet(data):
    src_addr, decrypted_data = layer0.b_decrypt(data)
    if MODE == "THREE":
        src_addr, decrypted_data = layer0.b_decrypt(decrypted_data[1])
        src_addr, decrypted_data = layer0.b_decrypt(decrypted_data[1])
    return src_addr, decrypted_data


def bytes_to_address(addr):
    addr = eval(addr)
    return Layer.hex_to_ip(addr[0]), int(addr[1])


def packet_handle():
    #  and not tcp.Ack and inbound
    # filter_expression = "(tcp.SrcPort == 55554 or tcp.DstPort == 55554) and outbound"
    filter_expression = "tcp and (tcp.SrcPort == 55554 or tcp.DstPort == 55554)"

    # Open a handle to the network stack
    with pydivert.WinDivert(filter_expression) as handle:
        for pkt in handle:
            print(pkt.src_addr, ":", pkt.src_port, "-->", pkt.dst_addr, ":", pkt.dst_port)

            # Access packet information
            if pkt.tcp.src_port == 55554:
                data = pkt.payload
                encrypted_data = encrypt_packet(data, pkt.ipv4.dst_addr, pkt.tcp.dst_port)
                pkt.payload = encrypted_data

                pkt.ip.dst_addr = nodes[0][0]
                pkt.tcp.dst_port = nodes[0][1]

            elif pkt.tcp.dst_port == 55554:
                try:
                    addr, data = decrypt_packet(pkt.payload)
                    pkt.payload = data

                    src_ip, src_port = bytes_to_address(addr)
                    pkt.src_addr = src_ip
                    pkt.src_port = src_port
                except ValueError:
                    print(pkt.tcp.ack, pkt.tcp.syn, pkt.tcp.rst, pkt.tcp.fin)
                    raise
            else:
                print("preposterous")

            handle.send(pkt)


if __name__ == '__main__':
    if len(sys.argv) > 1:
        personal_port = int(sys.argv[1])
    print("client started")
    packet_handle()

