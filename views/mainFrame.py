from tkinter import *
from tkinter.filedialog import askopenfilename
from views.addressFrame import Dialog
import tkinter as tk


class MainFrame(tk.Frame):
    def __init__(self, parent):
        tk.Frame.__init__(self, parent)

        address = Dialog(self, "Type address").show()
        password = Dialog(self, "Type password").show()

        self.configure(background="black")
        self.configure(bg='black')
        inputtxt = Text(self, height=3,
                        width=200,
                        bg="light yellow",
                        padx=10,
                        pady=10
                        )

        Output = Text(self, height=8,
                      width=200,
                      bg="light cyan",
                      padx=10,
                      pady=10)

        fileButton = Button(self, height=2,
                            width=20,
                            text="File",
                            command=lambda: self.Take_input(),
                            background="black",
                            fg="white"
                            )

        messAlgDesc = Label(text="Text algorithm:", background="black", fg="white")
        variable = StringVar(self)
        variable.set("ECB")
        messAlgChooser = OptionMenu(self, variable, "ECB", "CBC")
        messAlgChooser.config(bg="black", fg="white")

        fileAlgDesc = Label(text="File algorithm:", background="black", fg="white")
        variable = StringVar(self)
        variable.set("OFB")
        fileAlgChooser = OptionMenu(self, variable, "OFB", "CBC")
        fileAlgChooser.config(bg="black", fg="white")

        fileButton.grid(row=2, column=0)
        messAlgDesc.grid(row=1, column=0, sticky="nw")
        messAlgChooser.grid(row=1, column=0, sticky="ne")
        fileAlgDesc.grid(row=1, column=0, sticky="sw")
        fileAlgChooser.grid(row=1, column=0, sticky="se")
        Output.grid(row=1, column=1)
        inputtxt.grid(row=3, column=1)

        mainloop()

    def Take_input(self):
        filename = askopenfilename()
