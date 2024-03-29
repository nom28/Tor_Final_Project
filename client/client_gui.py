import customtkinter
from tkinter import *
from tkinter import filedialog as fd
import os
from PIL import Image
import time
import queue
from threading import Thread
import os
import configparser
import pickle

from client import Client
import tools.toolbox as tb


class App(customtkinter.CTk):
    c = Client()
    local_dir = ""
    signedin = False

    buffer = 0
    designated_file_name = ""
    temp_mem = b''

    download_amount = 0
    items_downloaded = 0
    upload_amount = 0

    def __init__(self):
        super().__init__()

        self.config = configparser.ConfigParser()
        self.config.read('client_files/client_settings.ini')
        dir = self.config.get('Directories', 'LocalDir')
        if dir:
            self.local_dir = dir

        self.title("PASTA")
        self.geometry("700x450")
        self.minsize(width=700, height=450)

        # set grid layout 1x2
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # load images with light and dark mode image
        image_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "client_files/test_images")
        self.logo_image = customtkinter.CTkImage(
            light_image=Image.open(os.path.join(image_path, "PASTA_logo_dark.png")),
            dark_image=Image.open(os.path.join(image_path, "PASTA_logo_light.png")), size=(60, 30))
        self.home_image = customtkinter.CTkImage(
            light_image=Image.open(os.path.join(image_path, "home_dark.png")),
            dark_image=Image.open(os.path.join(image_path, "home_light.png")), size=(20, 20))
        self.upload_image = customtkinter.CTkImage(
            light_image=Image.open(os.path.join(image_path, "upload_dark.png")),
            dark_image=Image.open(os.path.join(image_path, "upload_light.png")), size=(20, 20))
        self.download_image = customtkinter.CTkImage(
            light_image=Image.open(os.path.join(image_path, "download_dark.png")),
            dark_image=Image.open(os.path.join(image_path, "download_light.png")), size=(20, 20))
        self.settings_image = customtkinter.CTkImage(
            light_image=Image.open(os.path.join(image_path, "settings_dark.png")),
            dark_image=Image.open(os.path.join(image_path, "settings_light.png")), size=(20, 20))

        # create navigation frame
        self.navigation_frame = customtkinter.CTkFrame(self, corner_radius=0)
        self.navigation_frame.grid(row=0, column=0, sticky="nsew")
        self.navigation_frame.grid_rowconfigure(4, weight=1)

        self.navigation_frame_label = customtkinter.CTkLabel(self.navigation_frame, text="  PASTA",
                                                             image=self.logo_image, compound="left",
                                                             font=customtkinter.CTkFont(size=15, weight="bold"))
        self.navigation_frame_label.grid(row=0, column=0, padx=20, pady=20)

        self.home_button = customtkinter.CTkButton(self.navigation_frame, corner_radius=0, height=40,
                                                   border_spacing=10, text="Home",
                                                   fg_color="transparent", text_color=("gray10", "gray90"),
                                                   hover_color=("gray70", "gray30"),
                                                   image=self.home_image, anchor="w",
                                                   command=self.home_button_event)
        self.home_button.grid(row=1, column=0, sticky="new")

        self.frame_2_button = customtkinter.CTkButton(self.navigation_frame, corner_radius=0, height=40,
                                                      border_spacing=10, text="Upload",
                                                      fg_color="transparent", text_color=("gray10", "gray90"),
                                                      hover_color=("gray70", "gray30"),
                                                      image=self.upload_image, anchor="w",
                                                      command=self.frame_2_button_event)
        self.frame_2_button.grid(row=2, column=0, sticky="new")

        self.frame_3_button = customtkinter.CTkButton(self.navigation_frame, corner_radius=0, height=40,
                                                      border_spacing=10, text="Download",
                                                      fg_color="transparent", text_color=("gray10", "gray90"),
                                                      hover_color=("gray70", "gray30"),
                                                      image=self.download_image, anchor="w",
                                                      command=self.frame_3_button_event)
        self.frame_3_button.grid(row=3, column=0, sticky="new")

        self.frame_4_button = customtkinter.CTkButton(self.navigation_frame, corner_radius=0, height=40,
                                                      border_spacing=10, text="Settings",
                                                      fg_color="transparent", text_color=("gray10", "gray90"),
                                                      hover_color=("gray70", "gray30"),
                                                      image=self.settings_image, anchor="w",
                                                      command=self.frame_4_button_event)
        self.frame_4_button.grid(row=4, column=0, sticky="new")

        self.update_label = customtkinter.CTkLabel(self.navigation_frame, text="", text_color=("gray10", "gray90"),
                                                   compound="left", font=("arial", 12))
        self.update_label.grid(row=6, column=0, padx=20, pady=10, sticky="sw")

        self.appearance_mode_menu = customtkinter.CTkOptionMenu(self.navigation_frame, values=["Dark", "Light"],
                                                                command=self.change_appearance_mode_event)
        self.appearance_mode_menu.grid(row=7, column=0, padx=20, pady=20, sticky="s")

        # create home frame signup
        self.home_frame_signup = customtkinter.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.home_frame_signup.grid_columnconfigure(0, weight=1)

        self.signup_label = customtkinter.CTkLabel(self.home_frame_signup, text="Sign Up", font=("Arial", 18))
        self.signup_label.grid(row=0, column=0, padx=20, pady=20)

        self.signup_frame = customtkinter.CTkFrame(master=self.home_frame_signup)
        self.signup_frame.grid(row=1, column=0, padx=20, pady=10)

        signup_info = """To sign-up, no info is needed. 
        Although, please note
        to gain access to your files
        you MUST write down your hash and 2FA code"""
        self.signup_info_label = customtkinter.CTkLabel(master=self.signup_frame, text=signup_info)
        self.signup_info_label.grid(row=0, column=0, padx=30, pady=20)

        self.signup_button = customtkinter.CTkButton(master=self.signup_frame, text='Sign up', command=self.signup)
        self.signup_button.grid(row=1, column=0, padx=20, pady=10)

        self.switch_in_button = customtkinter.CTkButton(master=self.home_frame_signup, text='Sign In',
                                                        command=lambda: self.select_frame_by_name("home signin"))
        self.switch_in_button.grid(row=2, column=0, padx=20, pady=10)

        # create home frame signin
        self.home_frame_signin = customtkinter.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.home_frame_signin.grid_columnconfigure(0, weight=1)

        self.signin_label = customtkinter.CTkLabel(self.home_frame_signin, text="Sign In", font=("Arial", 18))
        self.signin_label.grid(row=0, column=0, padx=20, pady=20)

        self.signin_frame = customtkinter.CTkFrame(master=self.home_frame_signin)
        self.signin_frame.grid(row=1, column=0, padx=20, pady=10)

        self.hash_entry = customtkinter.CTkEntry(master=self.signin_frame, placeholder_text="User Hash")
        self.hash_entry.grid(row=0, column=0, padx=20, pady=10)

        self.auth_entry = customtkinter.CTkEntry(master=self.signin_frame, placeholder_text="2FA")
        self.auth_entry.grid(row=1, column=0, padx=20, pady=10)

        self.signin_button = customtkinter.CTkButton(master=self.signin_frame, text='Sign In', command=self.signin)
        self.signin_button.grid(row=2, column=0, padx=20, pady=10)

        self.switch_up_button = customtkinter.CTkButton(master=self.home_frame_signin, text='Sign Up',
                                                        command=lambda: self.select_frame_by_name("home signup"))
        self.switch_up_button.grid(row=2, column=0, padx=20, pady=10)

        # create home info frame
        self.home_info = customtkinter.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.home_info.grid_columnconfigure(0, weight=1)

        self.info_label = customtkinter.CTkLabel(self.home_info, text="Home - Info", font=("Arial", 18))
        self.info_label.grid(row=0, column=0, padx=20, pady=20)

        self.auth_label = customtkinter.CTkLabel(self.home_info, text="", font=("Arial", 14), text_color="#2E86C1")
        self.auth_label.grid(row=1, column=0, padx=10, pady=10)

        with open("client_files/info.txt", "r") as i:
            info = i.read()
        self.info_block_label = customtkinter.CTkLabel(self.home_info, text=info, font=("Arial", 14))
        self.info_block_label.grid(row=2, column=0, padx=20, pady=20)

        # create second frame
        self.second_frame = customtkinter.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.second_frame.grid_columnconfigure(0, weight=1)

        self.upload_label = customtkinter.CTkLabel(self.second_frame, text="Upload from local", font=("Arial", 18))
        self.upload_label.grid(row=0, column=0, padx=20, pady=20)

        self.scrollable_frame_1 = customtkinter.CTkScrollableFrame(master=self.second_frame)
        self.scrollable_frame_1.grid(row=1, column=0, padx=20, pady=20, sticky="nsew")

        self.upload_button = customtkinter.CTkButton(master=self.second_frame, text='Upload')
        self.upload_button.grid(row=2, column=0, padx=20, pady=10)

        # create third frame
        self.third_frame = customtkinter.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.third_frame.grid_columnconfigure(0, weight=1)

        self.download_label = customtkinter.CTkLabel(self.third_frame, text="Download from cloud", font=("Arial", 18))
        self.download_label.grid(row=0, column=0, padx=20, pady=20)

        self.scrollable_frame_2 = customtkinter.CTkScrollableFrame(master=self.third_frame)
        self.scrollable_frame_2.grid(row=1, column=0, padx=20, pady=20, sticky="nsew")

        self.download_button = customtkinter.CTkButton(master=self.third_frame, text='Download')
        self.download_button.grid(row=2, column=0, padx=20, pady=10)

        # create fourth frame
        self.fourth_frame = customtkinter.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.fourth_frame.grid_columnconfigure(0, weight=1)

        self.settings_label = customtkinter.CTkLabel(self.fourth_frame, text="Settings", font=("Arial", 18))
        self.settings_label.grid(row=0, column=0, padx=20, pady=20)

        self.settings_frame = customtkinter.CTkFrame(master=self.fourth_frame)
        self.settings_frame.grid(row=1, column=0, padx=20, pady=10)

        self.settings_entry = customtkinter.CTkEntry(master=self.settings_frame, placeholder_text="Directory")
        self.settings_entry.grid(row=0, column=0, padx=20, pady=10)

        self.settings_label = customtkinter.CTkLabel(self.settings_frame, text="Or")
        self.settings_label.grid(row=0, column=1, padx=20, pady=20)

        self.choose_dir_button = customtkinter.CTkButton(master=self.settings_frame, text='Directory',
                                                         command=self.choose_local_directory_button_event)
        self.choose_dir_button.grid(row=0, column=2, padx=20, pady=10)

        self.settings_save_button = customtkinter.CTkButton(master=self.settings_frame, text='Save',
                                                            command=self.settings_save_button_event)
        self.settings_save_button.grid(row=1, column=0, columnspan=3, padx=10, pady=20)

        # select default frame
        self.select_frame_by_name("home signin")
        self.change_appearance_mode_event("Dark")

        # communications
        self.code_to_func = {
            b'\x9d\xb7\xe3': self.upload_complete,
            b'\x98\x16\xac': self.file_list,
            b'\xd3\xb6\xad': self.error_update,
            b'\xa7\x98\xa8': self.download_save,
            b'\x9d\xf6\x9e': self.signup_successful,
            b'\xc6\xbd\x06': self.signin_successful,
            b'\xf2\xee\x07': self._update_label
        }

        analyzer = Thread(target=self.analyzer)
        analyzer.daemon = True
        analyzer.start()

    def analyzer(self):
        while True:
            if not self.c.ready_q.empty():
                try:
                    d = self.c.ready_q.get()
                    key = d[:3]
                    data = d[3:]
                    print(data)
                    self.code_to_func[key](data)
                except KeyError as e:
                    print("Error", e)
            else:
                time.sleep(0)

    def _update_label(self, msg):
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        self.update_label.configure(text=f"[{timestamp}] {msg.decode('utf-8')}", text_color=("gray10", "gray90"))

    def error_update(self, msg):
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        self.update_label.configure(text=f"[{timestamp}] {msg.decode('utf-8')}", text_color="red")

    def signup_successful(self, msg):
        h, tfa = pickle.loads(msg)
        self.signedin = True
        self.update_label.configure(text="")
        self.auth_label.configure(text=f'Your User Hash:\n"{str(h)}"\nYour 2FA key:\n"{str(tfa)}"\n')
        self.select_frame_by_name("home info")

    def signin_successful(self, msg):
        self.signedin = True
        self.update_label.configure(text="")
        self.auth_label.configure(text="")
        self.select_frame_by_name("home info")

    def select_frame_by_name(self, name):
        if not self.signedin and (name == "download" or name == "upload"):
            return

        # set button color for selected button
        self.home_button.configure(fg_color=("gray75", "gray25") if name.split(" ")[0] == "home" else "transparent")
        self.frame_2_button.configure(fg_color=("gray75", "gray25") if name == "upload" else "transparent")
        self.frame_3_button.configure(fg_color=("gray75", "gray25") if name == "download" else "transparent")
        self.frame_4_button.configure(fg_color=("gray75", "gray25") if name == "settings" else "transparent")


        # show selected frame
        if name == "home info":
            self.home_info.grid(row=0, column=1, sticky="nsew")
        else:
            self.home_info.grid_forget()
        if name == "home signin":
            self.home_frame_signin.grid(row=0, column=1, sticky="nsew")
        else:
            self.home_frame_signin.grid_forget()
        if name == "home signup":
            self.home_frame_signup.grid(row=0, column=1, sticky="nsew")
        else:
            self.home_frame_signup.grid_forget()
        if name == "upload":
            self.second_frame.grid(row=0, column=1, sticky="nsew")
        else:
            self.second_frame.grid_forget()
        if name == "download":
            self.third_frame.grid(row=0, column=1, sticky="nsew")
        else:
            self.third_frame.grid_forget()
        if name == "settings":
            self.fourth_frame.grid(row=0, column=1, sticky="nsew")
        else:
            self.fourth_frame.grid_forget()

    def home_button_event(self):
        if self.signedin:
            self.select_frame_by_name("home info")
        else:
            self.select_frame_by_name("home signin")

    def frame_2_button_event(self):
        self.select_frame_by_name("upload")
        # this includes an if statement to remove any directories
        files = [f for f in os.listdir(self.local_dir) if os.path.isfile(os.path.join(self.local_dir, f))]
        variables = []

        # Destroy previous lines
        for widget in self.scrollable_frame_1.winfo_children():
            widget.grid_forget()
            widget.destroy()

        # Apply new lines
        for i, file in enumerate(files):
            variables.append(customtkinter.StringVar(value="off"))
            checkbox = customtkinter.CTkCheckBox(self.scrollable_frame_1, text=file, variable=variables[i],
                                                 onvalue="on", offvalue="off")
            checkbox.grid(row=i, column=0, pady=10, padx=10, sticky="w")

        self.upload_button.configure(command=lambda: self.upload(files, variables))

    def upload(self, files, variables):
        relevant_files = []
        for i, var in enumerate(variables):
            if var.get() == "on":
                relevant_files.append(files[i])

        self.upload_button.configure(state="disabled")
        self.upload_amount = len(relevant_files)
        for file in relevant_files:
            with open(self.local_dir+"/"+file, "rb") as i:
                data = i.read()
                # print("length:", len(data))
                self.c.send(file.encode(), b"U")
                self.c.send(data, b"U")

    def upload_complete(self, msg):
        self.upload_amount -= 1
        if self.upload_amount:
            return

        self.upload_button.configure(state="normal")
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        self.update_label.configure(text=f"[{timestamp}] Upload finished", text_color=("gray10", "gray90"))

    def frame_3_button_event(self):
        self.select_frame_by_name("download")
        if self.signedin:
            self.c.send(b"0", b"L")  # first argument is the page number

    def frame_4_button_event(self):
        self.select_frame_by_name("settings")

    def choose_local_directory_button_event(self):
        dir = fd.askdirectory()
        print(dir)
        self.settings_entry.insert(0, dir)

    def settings_save_button_event(self):
        dir = self.settings_entry.get()
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        if not dir or not os.path.exists(dir):
            self.update_label.configure(text=f"[{timestamp}] Dir doesn't exist", text_color="red")
            return

        self.config.read('client_files/client_settings.ini')
        self.config.set('Directories', 'localdir', dir)

        with open('client_files/client_settings.ini', 'w') as configfile:
            self.config.write(configfile)
        self.update_label.configure(text=f"[{timestamp}] Dir updated", text_color="green")

        self.local_dir = dir

    def change_appearance_mode_event(self, new_appearance_mode):
        customtkinter.set_appearance_mode(new_appearance_mode)

    def signup(self):
        self.c.send(b"0", b"S")

    def signin(self):
        h = self.hash_entry.get()
        auth2fa = self.auth_entry.get()
        self.c.send(pickle.dumps([h, auth2fa]), b"I")

    def file_list(self, data):
        files = eval(data)
        variables = []
        # Destroy previous lines
        for widget in self.scrollable_frame_2.winfo_children():
            widget.grid_forget()  # for some reason raises error without forgetting before destroying
            widget.destroy()
        # Apply new lines
        for i, file in enumerate(files):
            variables.append(customtkinter.StringVar(value="off"))
            checkbox = customtkinter.CTkCheckBox(self.scrollable_frame_2, text=file, variable=variables[i],
                                                 onvalue="on", offvalue="off")
            checkbox.grid(row=i, column=0, pady=10, padx=10, sticky="w")

        self.download_button.configure(command=lambda: self.download(files, variables))

    def download(self, files, variables):
        if self.download_amount != self.items_downloaded:
            print("your previous download did not finish for some reason")
            return
        relevant_files = []
        for i, var in enumerate(variables):
            if var.get() == "on":
                relevant_files.append(files[i])

        self.download_amount = len(relevant_files)
        self.download_button.configure(state="disabled")
        self.c.send(str(relevant_files).encode('utf-8'), b"D")

    def download_save(self, data):
        if self.designated_file_name:
            self.save(data)
        else:
            self.designated_file_name = data.decode()

    def save(self, data):
        with open(f"{self.local_dir}/{self.designated_file_name}", "wb") as i:
            i.write(data)

        self.items_downloaded += 1
        print("download amount left:", self.download_amount - self.items_downloaded)
        self.designated_file_name = ""

        if self.download_amount != self.items_downloaded:
            self.update_label.configure(text=f"[{self.items_downloaded + 1}/{self.download_amount}]",
                                        text_color=("gray10", "gray90"))
            return

        self.download_amount = 0
        self.items_downloaded = 0
        self.download_button.configure(state="normal")
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        self.update_label.configure(text=f"[{timestamp}] Download finished", text_color=("gray10", "gray90"))


if __name__ == "__main__":
    app = App()
    app.mainloop()