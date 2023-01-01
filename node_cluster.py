import subprocess
from threading import *
import random
port = 55556
nodes = []


def run_node(port, key_num):
    subprocess.run(f"python node.py {port} {key_num}")


for x in range(1, 4):
    nodes.append(Thread(target=run_node, args=(port, x)))
    # nodes[x-1].daemon = True
    nodes[x-1].start()
    port += 1
print(nodes)



