import logging
from client.mainFrame import MainFrame
import tkinter as tk

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger().setLevel(logging.DEBUG)
    log = logging.getLogger(__name__)
    log.info("________BSK MESSENGER________")
    root = tk.Tk()
    root.geometry("500x300")
    root.title(" BSK Messenger")
    frame = MainFrame(root)
    root.mainloop()
