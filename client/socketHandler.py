import socket
import threading
import logging
import pickle
from tkinter import END

from message.message import Message, MessageTypes

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


class SocketHandler:
    FORMAT = 'utf-8'

    def __init__(self, port: int, address: str, output):
        self.port = int(port)
        self.address = address
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.isConnectionActive = False
        self.output = output

        self.connectionThread = threading.Thread(target=self.connect)
        self.connectionThread.start()
        self.receiveThread = threading.Thread(target=self.receive)
        self.receiveThread.start()

    def connect(self):
        while True:
            if not self.isConnectionActive:
                log.info('Connecting to socket')
                try:
                    self.socket.connect((self.address, self.port))
                except:
                    log.info('Not connected to socket')
                    continue
                log.info('Connected to socket')
                self.isConnectionActive = True

    def receive(self):
        while True:
            if self.isConnectionActive:
                try:
                    msg = self.socket.recv(1024)
                    log.info('Received message')
                    msg = pickle.loads(msg)
                    self.output.insert(END, "\n"+msg.content)
                except Exception as e:
                    log.info(f'Error receiving message {e}')

    def sendMessage(self, content):
        log.info('TypedEnter')
        if self.isConnectionActive:
            log.info('Sending text message')
            try:
                msg = Message(MessageTypes.TEXT, content)
                self.socket.sendall(pickle.dumps(msg))
            except ConnectionResetError as e:
                self.isConnectionActive = False

    def sendFile(self, filename):
        log.info('FileChosen')
