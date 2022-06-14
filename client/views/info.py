import tkinter as tk
from tkinter import *


class Info(object):
    def __init__(self, parent, label):
        self.toplevel = tk.Toplevel(parent)
        self.toplevel.geometry("300x80")
        self.toplevel.configure(bg='black')
        self.toplevel.configure(background="black")
        self.text = Label(self.toplevel, text=label, background="black", fg="white")
        self.button = tk.Button(self.toplevel, text="OK", command=self.close)

        self.text.pack(side="top")
        self.button.pack()
        self.value = ""

    def close(self):
        self.toplevel.destroy()

    def show(self):
        self.toplevel.deiconify()
        self.toplevel.wait_window()
        return
