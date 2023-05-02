import tkinter as tk
from tkinter.filedialog import askopenfilename
import queue
from threading import *

from client import Client


class Gui:
    c = Client()

    def __init__(self):
        self.root = tk.Tk()
        self.root.geometry('150x150')
        self.button1 = tk.Button(self.root, text="upload", width=10, height=2, bg="light grey", fg="black", command=self.upload)
        self.button2 = tk.Button(self.root, text="download", width=10, height=2, bg="light grey", fg="black")

        self.button1.pack(pady=1)
        self.button2.pack(pady=1)

        self.comms_setup()
        self.root.mainloop()

    def comms_setup(self):
        sniffer = Thread(target=self.c.sniffer)
        sniffer.daemon = True
        sniffer.start()

    def upload(self):
        self.lock_root()
        fn = askopenfilename()
        try:
            with open(fn, "rb") as i:
                self.c.send(i.read())
            self.release_root()
        except Exception:
            raise Exception

    def lock_root(self):
        for w in self.root.winfo_children():
            print(w)
            w.configure(state="disabled")

    def release_root(self):
        for w in self.root.winfo_children():
            print(w)
            w.configure(state="normal")



if __name__ == '__main__':
    t = Gui()
