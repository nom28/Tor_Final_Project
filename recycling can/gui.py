import time
import tkinter as tk
from tkinter.filedialog import askdirectory, askopenfilenames
import tkinter.messagebox as messagebox
import queue
from threading import Thread
import os
import configparser
import pickle

from client import Client
import tools.toolbox as tb


class Gui:
    c = Client()
    incoming_msgs = queue.Queue()
    local_dir = ""

    buffer = 0
    designated_file_name = ""
    temp_mem = b''

    download_page_num = 0

    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config.read('tools/client_settings.ini')
        dir = self.config.get('Directories', 'LocalDir')
        if dir:
            self.local_dir = dir

        self.root = tk.Tk()
        self.root.geometry('150x170')
        self.root.configure(bg='white')

        # Settings button gif
        img = tk.PhotoImage(file="client_files/63-settings-cog.gif")
        label = tk.Label(self.root, image=img, background='white')  # without "background='white'" is button-ier
        label.bind("<Button-1>", self.b_settings)
        label.grid(column=0, row=0, padx=1, pady=1)

        # Actually button
        self.button1 = tk.Button(self.root, text="upload", width=10, height=2, bg="light grey", fg="black",
                                 command=self.b_upload)
        self.button2 = tk.Button(self.root, text="download", width=10, height=2, bg="light grey", fg="black",
                                 command=self.b_download)
        """self.button3 = tk.Button(self.root, text="set local dir", width=10, height=2, bg="light grey", fg="black",
                                 command=self.b_set_local_dir)"""

        self.button1.grid(column=1, row=1, pady=8, padx=10)
        self.button2.grid(column=1, row=2, pady=8, padx=10)
        """self.button3.grid(column=1, row=3, pady=8, padx=5)"""

        if not self.local_dir:
            self.button2.configure(state="disabled")

        self.code_to_func = {
            b'\x9d\xb7\xe3': self.info_popbox,
            b'\x98\x16\xac': self.file_list_cloud,
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

    def b_settings(self, event):
        settings = tk.Toplevel(self.root, name='settings')
        settings.title("Picture List")
        settings.geometry("150x100")

        tk.Label(settings, text="Settings", font="Helvetica 10 bold").grid(row=0, column=0, pady=5)

        dir_button = tk.Button(settings, text="set local dir", width=10, height=2, bg="light grey", fg="black",
                               command=self.b_set_local_dir)

        dir_button.grid(row=1, column=0, padx=35)


    def b_upload(self):
        self.lock_root()
        fns = askopenfilenames()
        if fns == '':  # prevents error if user decides to cancel
            self.release_root()
            return
        try:
            for fn in fns:
                print(fn)
                with open(fn, "rb") as i:
                    data = i.read()
                    self.c.send(pickle.dumps([len(data), fn.split("/")[-1]]), b"U")  # [size, name + type]
                    self.c.send(data, b"U")
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

    def error_popbox(self, msg):
        if msg == b"page does not exist":
            self.download_page_num -= 1
        messagebox.showerror("Error", str(msg))

    def file_list_cloud(self, data):
        for w in self.root.winfo_children():
            if w.winfo_name() != "downloads":
                continue
            for item in w.winfo_children():
                item.destroy()
            self.add_options(w, eval(data))
            return
        self.top_window(data)

    def top_window(self, data):
        # self.download_page_num = 0  # default value
        try:
            files = eval(data)
        except Exception as e:
            raise

        window = tk.Toplevel(self.root, name="downloads")
        window.title("Picture List")
        window.geometry("300x300")

        self.add_options(window, files)

    def add_options(self, window, files):
        _vars = []
        for i, file in enumerate(files):
            var = tk.IntVar()
            c = tk.Checkbutton(window, text=file, variable=var, onvalue=1, offvalue=0)
            c.grid(row=i, column=0, columnspan=3, padx=20, sticky="w")
            _vars.append(var)

        d_button = tk.Button(window, text="Download", width=10, height=2, bg="light grey", fg="black",
                             command=lambda: self.download(_vars, files))
        d_button.grid(row=i + 1, column=0, padx=15)

        l_button = tk.Button(window, text="<", width=2, height=1, bg="light grey", fg="black",
                             command=lambda: self.move_page(-1))
        r_button = tk.Button(window, text=">", width=2, height=1, bg="light grey", fg="black",
                             command=lambda: self.move_page(1))

        l_button.grid(row=i + 1, column=1)
        r_button.grid(row=i + 1, column=2)

    def move_page(self, offset):
        if self.download_page_num == 0 and offset < 0:
            return
        self.download_page_num = self.download_page_num + offset
        self.c.send(str(self.download_page_num).encode(), b"L")

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
            data = pickle.loads(data)
            self.buffer = data[0]
            self.designated_file_name = data[1]
            print("buffer:", self.buffer)
        return

    def save(self, data):
        self.temp_mem += data

        self.buffer -= len(data)
        print("buffer:", self.buffer)
        if self.buffer <= 0:
            i = int(time.time() * 10000)

            with open(f"{self.local_dir}/{self.designated_file_name}", "wb") as i:
                i.write(self.temp_mem)
                print("saving")
            self.buffer = 0
            self.designated_file_name = ""
            self.temp_mem = b''
            print("saved")


if __name__ == '__main__':
    t = Gui()
