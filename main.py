from tkinter import *
from tkinter.filedialog import askopenfilename

root = Tk()
root.geometry("500x300")
root.title(" BSK Messenger")
root.configure(background="black")
root.configure(bg='black')

def Take_input():
    filename = askopenfilename()


inputtxt = Text(root, height=3,
                width=200,
                bg="light yellow",
                padx=10,
                pady=10
                )

Output = Text(root, height=8,
              width=200,
              bg="light cyan",
              padx=10,
              pady=10)

fileButton = Button(root, height=2,
                    width=20,
                    text="File",
                    command=lambda: Take_input(),
                    background="black",
                    fg="white"
                    )

messAlgDesc = Label(text="Text algorithm:", background="black", fg="white")
variable = StringVar(root)
variable.set("ECB")
messAlgChooser = OptionMenu(root, variable, "ECB", "CBC")
messAlgChooser.config(bg="black", fg="white")

fileAlgDesc = Label(text="File algorithm:", background="black", fg="white")
variable = StringVar(root)
variable.set("OFB")
fileAlgChooser = OptionMenu(root, variable, "OFB", "CBC")
fileAlgChooser.config(bg="black", fg="white")

fileButton.grid(row=2, column=0)
messAlgDesc.grid(row=1, column=0, sticky="nw")
messAlgChooser.grid(row=1, column=0, sticky="ne")
fileAlgDesc.grid(row=1, column=0, sticky="sw")
fileAlgChooser.grid(row=1, column=0, sticky="se")
Output.grid(row=1, column=1)
inputtxt.grid(row=3, column=1)

mainloop()
