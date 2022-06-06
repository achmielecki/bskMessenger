from tkinter import *
from tkinter import ttk

root = Tk()
root.geometry("300x70")
root.title(" BSK Messenger")
root.configure(background="black")
root.configure(bg='black')

text = Label(text="Sending file...", background="black", fg="white")

pb = ttk.Progressbar(
    root,
    orient='horizontal',
    mode='determinate',
    length=280
)
pb['value'] = 39

text.pack(side="top")
pb.pack(side="bottom", pady=5)

root.mainloop()