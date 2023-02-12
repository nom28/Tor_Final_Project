import multiprocessing
import threading
import subprocess
import random  # NOQA
import time
port = 55556
nodes = []
default = 55560

def run_node(self_port, key_num, default):
    subprocess.run(f"python node.py {self_port} {key_num} {default}")


if __name__ == '__main__':
    for x in range(1, 4):
        # multiprocessing.Process(target=run_node, args=(port, x, default))
        nodes.append(threading.Thread(target=run_node, args=(port, x, default)))
        # nodes[x-1].daemon = True
        nodes[x-1].start()
        default += 10
        port += 1
        time.sleep(0.1)
    print(nodes)
    nodes[0].join()
    nodes[1].join()
    nodes[2].join()
