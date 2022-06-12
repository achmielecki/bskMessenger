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
            # TODO lepiej zawsze pytac o haslo
            # self.password = Dialog(self, "Type password").show()

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
                                 command=lambda: self.sendFile(),
                                 background="black",
                                 fg="white"
                                 )

        self.socketHandler = SocketHandler(self.port, self.address, self.output)

        self.othersListVar = StringVar(self)
        self.othersListVar.set(self.socketHandler.otherClients)
        self.othersListOption = OptionMenu(parent, self.othersListVar, "")

        self.refreshButton = tk.Button(parent, text='Refresh list', command=self.refreshOthersList)

        self.messAlgDesc = Label(parent, text="Text algorithm:", background="black", fg="white")
        self.algvariable = StringVar(self)
        self.algvariable.set("CBC")
        self.messAlgChooser = OptionMenu(parent, self.algvariable, "CBC", "ECB")
        self.messAlgChooser.config(bg="black", fg="white")

        self.fileAlgDesc = Label(text="File algorithm:", background="black", fg="white")
        self.filevariable = StringVar(self)
        self.filevariable.set("OFB")
        self.fileAlgChooser = OptionMenu(parent, self.filevariable, "OFB", "CBC")
        self.fileAlgChooser.config(bg="black", fg="white")

        self.fileButton.grid(row=2, column=0)
        self.messAlgDesc.grid(row=1, column=0, sticky="nw")
        self.messAlgChooser.grid(row=1, column=0, sticky="ne")
        self.fileAlgDesc.grid(row=1, column=0, sticky="sw")
        self.fileAlgChooser.grid(row=1, column=0, sticky="se")
        self.output.grid(row=1, column=1)
        self.inputtxt.grid(row=3, column=1)
        self.othersListOption.grid(row=1, column=0, sticky="w")
        self.refreshButton.grid(row=1, column=0, sticky="e")

        mainloop()

    def sendFile(self):
        filename = askopenfilename()
        self.socketHandler.sendFile(filename)

    def sendMessage(self, event=None):
        msg = self.inputtxt.get("1.0", 'end-1c')
        self.inputtxt.delete("1.0", 'end')
        receiver = self.othersListVar.get()
        encryption = self.algvariable.get()
        self.socketHandler.sendTextMessage(msg, receiver, encryption)
        self.output.insert(END, f"\n [{self.socketHandler.socket.getsockname()[0]}:{self.socketHandler.socket.getsockname()[1]}] {msg[:-1]}")
        self.output.see('end')

    def refreshOthersList(self):
        menu = self.othersListOption["menu"]
        menu.delete(0, "end")
        for entry in self.socketHandler.otherClients:
            menu.add_command(label=entry, command=lambda value=entry: self.othersListVar.set(value))
        #self.othersListVar.set(self.socketHandler.otherClients)
