from tkinter import *
from tkinter.filedialog import askopenfilename

root = Tk()
root.geometry("300x70")
root.title(" BSK Messenger")
root.configure(background="black")
root.configure(bg='black')

text = Label(text="Type address:", background="black", fg="white")


inputtxt = Text(root, height=1,
                width=30,
                bg="light yellow",
                padx=10,
                pady=10
                )

text.pack(side="top")
inputtxt.pack(side="bottom", pady=5)

mainloop()
