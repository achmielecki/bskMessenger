from tkinter import *
from tkinter import ttk


class Progressframe(object):
    def __init__(self):
        self.root = Tk()
        self.root.geometry("300x70")
        self.root.title(" BSK Messenger")
        self.root.configure(background="black")
        self.root.configure(bg='black')
        self.val = 0

        self.pb = ttk.Progressbar(
            self.root,
            maximum=100,
            orient='horizontal',
            mode='determinate',
            length=280
        )
        self.pb['value'] = 0

        self.pb.grid(row=0, column=0)

        self.root.update()

    def updateValue(self, val, maxVal):
        self.val = int(val * 100 / maxVal)
        self.pb['value'] = self.val
        self.root.title(f"Sending file... {self.val}%")
        self.root.update()
        if self.val >= 100:
            self.close()

    def close(self):
        self.root.destroy()
