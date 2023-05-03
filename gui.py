import time
import tkinter as tk
from tkinter.filedialog import askopenfilename, askdirectory
import tkinter.messagebox as messagebox
import queue
from threading import Thread
import os
import configparser

from client import Client
import tools.toolbox as tb

class Gui:
    c = Client()
    incoming_msgs = queue.Queue()
    local_dir = ""

    buffer = 0
    temp_mem = b''

    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config.read('tools/client_settings.ini')
        dir = self.config.get('Directories', 'LocalDir')
        if dir:
            self.local_dir = dir

        self.root = tk.Tk()
        self.root.geometry('150x150')
        self.button1 = tk.Button(self.root, text="upload", width=10, height=2, bg="light grey", fg="black",
                                 command=self.b_upload)
        self.button2 = tk.Button(self.root, text="download", width=10, height=2, bg="light grey", fg="black",
                                 command=self.b_download)
        self.button3 = tk.Button(self.root, text="set local dir", width=10, height=2, bg="light grey", fg="black",
                                 command=self.b_set_local_dir)

        self.button1.pack(pady=5)
        self.button2.pack(pady=5)
        self.button3.pack(pady=5)

        if not self.local_dir:
            self.button2.configure(state="disabled")

        self.code_to_func = {
            b'\x9d\xb7\xe3': self.info_popbox,
            b'\x98\x16\xac': self.top_window,
            b'\xd3\xb6\xad': self.error_popbox,
            b'\xa7\x98\xa8': self.download_save

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
                    raise
                    print(e)
            else:
                time.sleep(0)

    def b_upload(self):
        self.lock_root()
        fn = askopenfilename()
        if fn == '':  # prevents error if user decides to cancel
            self.release_root()
            return
        try:
            with open(fn, "rb") as i:
                self.c.send(i.read(), b"U")
            self.release_root()
        except Exception as e:
            raise e

    def b_set_local_dir(self):
        # Making sure directory is valid, if not ask for a new one.
        self.local_dir = askdirectory()
        if not self.local_dir:
            return
        if not os.path.isdir(self.local_dir):
            self.local_dir = ""
            return

        self.config.read('tools/client_settings.ini')
        self.config.set('Directories', 'LocalDir', self.local_dir)
        with open('tools/client_settings.ini', 'w') as c:
            self.config.write(c)
        self.button2.configure(state="normal")

    def b_download(self):
        print("requesting list")
        self.c.send(b"0", b"L")  # first argument is the page number

    def lock_root(self):
        for w in self.root.winfo_children():
            w.configure(state="disabled")

    def release_root(self):
        for w in self.root.winfo_children():
            if w == self.button2 and not self.local_dir:
                continue
            w.configure(state="normal")

    @staticmethod
    def info_popbox(msg):
        messagebox.showinfo("Info", str(msg))

    @staticmethod
    def error_popbox(msg):
        messagebox.showerror("Error", str(msg))

    def top_window(self, data):
        try:
            files = eval(data)
        except Exception as e:
            raise

        window = tk.Toplevel(self.root)
        window.title("Picture List")
        window.geometry("200x300")
        _vars = []
        for file in files:
            var = tk.IntVar()
            c = tk.Checkbutton(window, text=file, variable=var, onvalue=1, offvalue=0)
            c.pack()
            _vars.append(var)

        d_button = tk.Button(window, text="Download", width=10, height=2, bg="light grey", fg="black",
                             command=lambda: self.download(_vars, files))
        d_button.pack()

    def download(self, _vars, files):
        relevant_files = []
        for i, var in enumerate(_vars):
            if var.get():
                relevant_files.append(files[i])
        self.c.send(str(relevant_files).encode('utf-8'), b"D")

    def download_save(self, data):
        if self.buffer:
            self.save(data)
        else:
            self.buffer = tb.int_from_bytes(data)
            print("buffer:", self.buffer)
        return

    def save(self, data):
        self.temp_mem += data

        self.buffer -= len(data)
        print("buffer:", self.buffer)
        if self.buffer <= 0:
            i = int(time.time() * 10000)

            with open(f"{self.local_dir}/file_{i}.jpg", "wb") as i:
                i.write(self.temp_mem)
                print("saving")
            self.buffer = 0
            self.temp_mem = b''
            print("saved")


if __name__ == '__main__':
    t = Gui()
