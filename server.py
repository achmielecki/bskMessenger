import socket
import threading
import logging
import pickle

from message.message import Message

log = logging.getLogger(__name__)


class SocketHandler:
    HEADER_SIZE = 512
    FORMAT = 'utf-8'

    def __init__(self, port: int, address: str):
        self.port = int(port)
        self.address = address
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.address, self.port))
        self.connection = None

        self.thread = threading.Thread(target=self.wait_for_connection)
        self.thread.start()

    def wait_for_connection(self) -> None:
        log.info('SERVER STARTING')
        self.socket.listen()
        while True:
            conn, addr = self.socket.accept()
            thread = threading.Thread(target=self.handle_connection, args=(conn, addr))
            thread.start()

    def handle_connection(self, conn: socket, addr: str) -> None:
        connection = True
        while connection:
            msg_length = int(conn.recv(self.HEADER_SIZE).decode(self.FORMAT))
            if msg_length:
                msg = conn.recv(msg_length)
                msg = pickle.loads(msg)
            if msg:
                connection = self.handle_message(msg, addr, conn)

    def handle_message(self, msg: Message, addr: str, conn: socket) -> bool:
        return True
