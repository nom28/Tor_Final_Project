import multiprocessing
import subprocess

def run_node(port, default, key_num):
    subprocess.run(f"python node.py {port} {default} {key_num}")

port = 55556
default = 55560
nodes = []
NUMBER_OF_NODES = 3

if __name__ == '__main__':
    multiprocessing.freeze_support()

    for x in range(1, NUMBER_OF_NODES + 1):
        p = multiprocessing.Process(target=run_node, args=(port, default, x))
        nodes.append(p)
        p.start()
        default += 10
        port += 1
    print(nodes)

