import pydivert
import random
import sys

from tools.layer_new import Layer


layer0 = Layer()
layer0.change_keys("0")

layer1 = Layer()
layer1.change_keys("1")
layer2 = Layer()
layer2.change_keys("2")
layer3 = Layer()
layer3.change_keys("3")

session_id = random.randbytes(20)
ports = [55556, 55557, 55558, 55559]
ip = "10.0.0.24"
personal_port = 55555
finished = False


def encrypt_packet(data, dst_ip):
    encrypted_data = layer3.encrypt(data, session_id, dst_ip, str(ports[3]))
    encrypted_data = layer2.encrypt(encrypted_data, session_id, ip, str(ports[2]))
    encrypted_data = layer1.encrypt(encrypted_data, session_id, ip, str(ports[1]))
    return encrypted_data


def decrypt_packet(data):
    decrypted_data = layer0.b_decrypt(data)
    decrypted_data = layer0.b_decrypt(decrypted_data[1])
    decrypted_data = layer0.b_decrypt(decrypted_data[1])
    return decrypted_data


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
                """if pkt.tcp.ack:
                    print("ack1")
                    handle.send(pkt)
                    continue"""

                data = pkt.payload
                encrypted_data = encrypt_packet(data, pkt.ipv4.dst_addr)
                pkt.payload = encrypted_data
                pkt.tcp.dst_port = ports[0]


            elif pkt.tcp.dst_port == 55554:
                """if pkt.tcp.ack:
                    print("ack2")
                    handle.send(pkt)
                    continue"""

                print(pkt.payload)
                try:
                    data = decrypt_packet(pkt.payload)
                    pkt.payload = data
                except ValueError:
                    print(pkt)

            else:
                print("rogue packet humf")

            if pkt.dst_port == 55556:
                print("yeepie")
            handle.send(pkt)


if __name__ == '__main__':
    if len(sys.argv) > 1:
        personal_port = int(sys.argv[1])
        ports[3] = int(sys.argv[2])
    print("client started")
    packet_handle()

