import time
import tkinter as tk
from tkinter.filedialog import askopenfilename
import tkinter.messagebox as messagebox
import queue
from threading import *

from client import Client


class Gui:
    c = Client()
    incoming_msgs = queue.Queue()

    def __init__(self):
        self.root = tk.Tk()
        self.root.geometry('150x150')
        self.button1 = tk.Button(self.root, text="upload", width=10, height=2, bg="light grey", fg="black", command=self.upload)
        self.button2 = tk.Button(self.root, text="download", width=10, height=2, bg="light grey", fg="black")

        self.button1.pack(pady=1)
        self.button2.pack(pady=1)

        self.code_to_func = {
            b'\x9d\xb7\xe3': self.popbox,

        }

        analyzer = Thread(target=self.analyzer)
        analyzer.daemon = True
        analyzer.start()
        self.sniffer_setup()
        self.root.mainloop()

    def sniffer_setup(self):
        sniffer = Thread(target=self.c.sniffer, args=(self.incoming_msgs,))
        sniffer.daemon = True
        sniffer.start()

    def analyzer(self):
        while True:
            if not self.incoming_msgs.empty():
                try:
                    d = self.incoming_msgs.get()
                    key = d[:3]
                    data = d[3:]
                    self.code_to_func[key](data)
                except KeyError as e:
                    print(e)
            else:
                time.sleep(0)

    def upload(self):
        self.lock_root()
        fn = askopenfilename()
        if fn == '':  # prevents error if user decides to cancel
            return
        try:
            with open(fn, "rb") as i:
                self.c.send(i.read())
            self.release_root()
        except Exception as e:
            raise e

    def lock_root(self):
        for w in self.root.winfo_children():
            w.configure(state="disabled")

    def release_root(self):
        for w in self.root.winfo_children():
            w.configure(state="normal")

    def popbox(self, msg):
        messagebox.showinfo("Info", msg)


if __name__ == '__main__':
    t = Gui()
