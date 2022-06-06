import logging
from views.mainFrame import MainFrame
import tkinter as tk

if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("500x300")
    root.title(" BSK Messenger")
    frame = MainFrame(root)
    root.mainloop()
    logging.basicConfig(level=logging.INFO)
