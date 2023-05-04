import subprocess
from threading import *
import random
port = 55556
default = 55560
nodes = []
NUMBER_OF_NODES = 3


def run_node(port, default, key_num):
    subprocess.run(f"python node.py {port} {default} {key_num}")


for x in range(1, NUMBER_OF_NODES + 1):
    nodes.append(Thread(target=run_node, args=(port, default, x)))
    # nodes[x-1].daemon = True
    nodes[x-1].start()
    default += 10
    port += 1
print(nodes)



