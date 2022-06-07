from tkinter import *
from tkinter.filedialog import askopenfilename

from server import SocketHandler
from views.dialog import Dialog

from config import *
import tkinter as tk


class MainFrame(tk.Frame):
    def __init__(self, parent):
        tk.Frame.__init__(self, parent)

        if not localMode:
            self.address = Dialog(self, "Type your address").show()
            self.connectAddress = Dialog(self, "Type connect address").show()
            self.port = Dialog(self, "Type your port").show()
            self.connectPort = Dialog(self, "Type connect port").show()
            self.password = Dialog(self, "Type password").show()
        else:
            self.nr = Dialog(self, "1 or 2").show()
            self.port = 8080
            self.connectPort = 8081
            if self.nr == "2":
                self.port = 8081
                self.connectPort = 8080
            self.address = "localhost"
            self.connectAddress = "localhost"
            self.port = 8080
            self.connectPort = 8081
            self.password = "123"

        self.socketHandler = SocketHandler(self.port, self.address)

        parent.configure(background="black")
        parent.configure(bg='black')
        self.inputtxt = Text(parent, height=3,
                             width=200,
                             bg="light yellow",
                             padx=10,
                             pady=10
                             )

        self.Output = Text(parent, height=8,
                           width=200,
                           bg="light cyan",
                           padx=10,
                           pady=10)

        self.fileButton = Button(parent, height=2,
                                 width=20,
                                 text="File",
                                 command=lambda: self.Take_input(),
                                 background="black",
                                 fg="white"
                                 )

        self.messAlgDesc = Label(parent, text="Text algorithm:", background="black", fg="white")
        algvariable = StringVar(self)
        algvariable.set("ECB")
        self.messAlgChooser = OptionMenu(parent, algvariable, "ECB", "CBC")
        self.messAlgChooser.config(bg="black", fg="white")

        self.fileAlgDesc = Label(text="File algorithm:", background="black", fg="white")
        filevariable = StringVar(self)
        filevariable.set("OFB")
        self.fileAlgChooser = OptionMenu(parent, filevariable, "OFB", "CBC")
        self.fileAlgChooser.config(bg="black", fg="white")

        self.fileButton.grid(row=2, column=0)
        self.messAlgDesc.grid(row=1, column=0, sticky="nw")
        self.messAlgChooser.grid(row=1, column=0, sticky="ne")
        self.fileAlgDesc.grid(row=1, column=0, sticky="sw")
        self.fileAlgChooser.grid(row=1, column=0, sticky="se")
        self.Output.grid(row=1, column=1)
        self.inputtxt.grid(row=3, column=1)

        mainloop()

    def Take_input(self):
        filename = askopenfilename()
