import socket
import threading
import logging
import pickle

from message.message import Message, MessageTypes
from server.connection import Connection

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


class Server:

    def __init__(self, port: int, address: str):
        self.port = int(port)
        self.address = address
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.address, self.port))
        self.connections = {}

        self.listenThread = threading.Thread(target=self.awaitConnection)
        self.listenThread.start()

    def awaitConnection(self) -> None:
        log.info('Listening socket starting')
        self.socket.listen()
        while True:
            connection, address = self.socket.accept()
            thread = threading.Thread(target=self.handleConnection, args=(connection, address))
            thread.start()

    def handleConnection(self, connection, address) -> None:
        log.info(f'Connected {address}')
        isConnectionActive = True
        self.connections[address] = Connection(address, connection)
        while isConnectionActive:
            try:
                msg = connection.recv(1024)
                if msg:
                    self.handleMessage(msg, address, connection)
            except Exception as e:
                isConnectionActive = False
                log.info(f'Disconnected {address} {e}')
                self.connections[address] = None

    def handleMessage(self, msg: Message, address: str, connection: socket):
        log.info(f'Message from {address}')
        self.sendFrom(connection, address, msg)

    def sendFrom(self, connection, address, msg):
        for client in self.connections.values():
            if not client.address == address:
                client.connection.sendall(msg)
