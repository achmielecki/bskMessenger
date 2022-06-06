from tkinter import *
import tkinter as tk


class Dialog(object):
    def __init__(self, parent, label):
        self.toplevel = tk.Toplevel(parent)
        self.toplevel.geometry("300x80")
        self.toplevel.configure(bg='black')
        self.toplevel.configure(background="black")
        self.text = Label(self.toplevel, text=label, background="black", fg="white")
        self.inputtxt = Entry(self.toplevel,
                                       width=30,
                                       bg="light yellow"
                                       )
        self.button = tk.Button(self.toplevel, text="OK", command=self.close)

        self.text.pack(side="top")
        self.inputtxt.pack(side="bottom", pady=5)
        self.button.pack()
        self.value = ""

    def close(self):
        self.value = self.inputtxt.get()
        self.toplevel.destroy()

    def show(self):
        self.toplevel.deiconify()
        self.toplevel.wait_window()
        return self.value
