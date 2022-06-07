import tkinter as tk
from tkinter import *
from tkinter.filedialog import askopenfilename

from client.socketHandler import SocketHandler
from client.views.dialog import Dialog
from config import *


class MainFrame(tk.Frame):
    def __init__(self, parent):
        tk.Frame.__init__(self, parent)

        if not localMode:
            self.address = Dialog(self, "Type your address").show()
            self.port = Dialog(self, "Type your port").show()
            self.password = Dialog(self, "Type password").show()
        else:
            self.port = localPort
            self.address = localHost
            self.password = localPassword

        parent.configure(background="black")
        parent.configure(bg='black')
        self.inputtxt = Text(parent, height=3,
                             width=200,
                             bg="light yellow",
                             padx=10,
                             pady=10
                             )
        parent.bind('<Return>', self.sendMessage)

        self.output = Text(parent, height=8,
                           width=200,
                           bg="light cyan",
                           padx=10,
                           pady=10)

        self.fileButton = Button(parent, height=2,
                                 width=20,
                                 text="File",
                                 command=lambda: self.sendFile,
                                 background="black",
                                 fg="white"
                                 )

        self.socketHandler = SocketHandler(self.port, self.address, self.output)

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
        self.output.grid(row=1, column=1)
        self.inputtxt.grid(row=3, column=1)

        mainloop()

    def sendFile(self):
        filename = askopenfilename()
        self.socketHandler.sendFile(filename)

    def sendMessage(self, event=None):
        msg = self.inputtxt.get("1.0", 'end-1c')
        self.socketHandler.sendMessage(msg)
