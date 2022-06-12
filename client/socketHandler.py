import os.path
import socket
import sys
import threading
import logging
import pickle
import time
import math
import base64
from tkinter import END
from config import *

from message.message import Message, MessageType
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC



log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


class SocketHandler:
    HEADER_LENGTH = 1024

    def __init__(self, port: int, address: str, output):
        self.port = int(port)
        self.address = address
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.isConnectionActive = False
        self.output = output
        self.publicKeys = {}
        self.otherClients = []

        privateKeyFile = open("privateKey.key", "wb")
        publicKeyFile = open("publicKey.key", "wb")

        if os.path.getsize("privateKey.key") == 0 or os.path.getsize("publicKey.key") == 0:
            self.key = rsa.generate_private_key(
                backend=crypto_default_backend(),
                public_exponent=65537,
                key_size=2048
            )

            self.privateKey = self.key.private_bytes(
                crypto_serialization.Encoding.PEM,
                crypto_serialization.PrivateFormat.PKCS8,
                crypto_serialization.NoEncryption()
            )

            self.publicKey = self.key.public_key().public_bytes(
                crypto_serialization.Encoding.OpenSSH,
                crypto_serialization.PublicFormat.OpenSSH
            )

            privateKeyFile.write(self.encryptText(localPassword, self.privateKey))
            publicKeyFile.write(self.encryptText(localPassword, self.publicKey))
        else:
            self.privateKey = self.decryptText(localPassword, privateKeyFile)
            self.publicKey = self.decryptText(localPassword, publicKeyFile)

        privateKeyFile.close()
        publicKeyFile.close()

        self.sessionKeys = {}

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
                self.initSession()
            time.sleep(5)

    def initSession(self):
        msg = Message(self.socket.getsockname(), MessageType.SESSION, self.publicKey.decode("utf-8"))
        self.sendMessage(msg)

    def receive(self):
        while True:
            if self.isConnectionActive:
                try:
                    self.handleMessage(self.getNextMessage())
                except Exception as e:
                    log.info(f'Error receiving message {e}')

    def getNextMessage(self):
        #log.info('Received message')
        msg = self.socket.recv(1024)
        msgLength = int(msg.decode('utf-8'))
        msg = self.socket.recv(msgLength)
        return pickle.loads(msg)

    def handleMessage(self, message):
        log.info(f"Received message {message.type}")
        log.info(f"Received message {message.content}")
        if message.type == MessageType.TEXT:
            self.receiveTextMessage(message)
        if message.type == MessageType.FILE:
            self.saveToFile(message)
        if message.type == MessageType.SESSION:
            self.saveKeyAndSend(message)
        if message.type == MessageType.KEY:
            self.saveSessionKey(message)

    def receiveTextMessage(self, message):
        mode = modes.CBC
        decryptedContent = ""
        if message.encryption == "CBC":
            decryptedContent = self.decryptTextCBC(message.content, self.sessionKeys[message.sender])
        elif message.encryption == "ECB":
            decryptedContent = self.decryptTextECB(message.content, self.sessionKeys[message.sender])
        self.output.insert(END, f"\n [{message.sender[0]}:{message.sender[1]}] {decryptedContent}")

    def saveKeyAndSend(self, message):
        if message.sender not in self.publicKeys:
            self.otherClients.append(message.sender)
            self.publicKeys[message.sender] = message.content.encode("utf-8")
            msg = Message(self.socket.getsockname(), MessageType.SESSION, self.publicKey.decode("utf-8"), message.sender)
            self.sendMessage(msg)
        else:
            self.sessionKeys[message.sender] = os.urandom(16)
            msg = Message(self.socket.getsockname(), MessageType.KEY, self.sessionKeys[message.sender].decode("latin-1"), message.sender)
            self.sendMessage(msg)

    def saveSessionKey(self, message):
        self.sessionKeys[message.sender] = message.content.encode("latin-1")

    def saveToFile(self, message):
        messages = [message.content]
        while len(messages) != message.parts:
            msg = self.getNextMessage()
            log.info(f"Received {1 + msg.part} of {msg.parts}")
            messages.append(msg.content)
        with open(f'downloaded{message.fileExtension}', "w+b") as file:
            file.write(b''.join(messages))
        log.info(f"Wrote {len(messages)} parts")

    def sendTextMessage(self, content, receiver, encryptionMode):
        log.info('TypedEnter')
        if self.isConnectionActive:
            log.info('Sending text message')
            mode = modes.CBC
            encryptedContent = ""
            if(encryptionMode == "CBC"):
                encryptedContent = self.encryptTextCBC(content, self.sessionKeys[self.findSessionKey(receiver)])
            elif encryptionMode == "ECB":
                encryptedContent = self.encryptTextECB(content, self.sessionKeys[self.findSessionKey(receiver)])
            try:
                msg = Message(self.socket.getsockname(), MessageType.TEXT, encryptedContent, receiver, encryption=encryptionMode)
                self.sendMessage(msg)
            except ConnectionResetError as e:
                self.isConnectionActive = False

    def sendFile(self, filename):
        max = 1024 * 50
        log.info('FileChosen')
        if self.isConnectionActive:
            log.info('Sending file')
            fExtension = os.path.splitext(filename)[1]
            parts = math.ceil(os.path.getsize(filename) / max)
            with open(filename, 'r+b') as source:
                part = 0
                while True:
                    msg = Message(self.socket.getsockname(), MessageType.FILE, None, None, part, parts, fExtension)
                    data = source.read(max)
                    msg.content = data
                    self.sendMessage(msg)
                    log.info(f'Sent part {1 + part} of {parts}')
                    part += 1
                    if part == parts:
                        break

    def nextMessageSize(self, msg):
        bytes = str(len(msg)).encode("utf-8")
        bytes = bytes + b' ' * (self.HEADER_LENGTH - len(bytes))
        return bytes

    def sendMessage(self, message):
        # TODO cipher message
        dumped = pickle.dumps(message)
        log.info(f'sending message: {len(dumped)} bytes')
        log.info(f'sending message: {message.content}')
        self.socket.sendall(self.nextMessageSize(dumped))
        self.socket.sendall(dumped)

    def encryptText(self, password, plaintext):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=os.urandom(16),
            iterations=390000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        fernet = Fernet(key)
        encrypted = fernet.encrypt(plaintext)
        return encrypted

    def decryptText(self, password, ciphertext):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=os.urandom(16),
            iterations=390000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        fernet = Fernet(key)
        plaintext = fernet.decrypt(ciphertext)
        return plaintext

    def encryptTextCBC(self, plaintext, sessionkey):
        key = sessionkey
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padded_data = self.pad(iv + plaintext.encode("utf-8"), 16)
        log.info(iv + plaintext.encode("utf-8"))
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext

    def decryptTextCBC(self, ciphertext, sessionkey):
        key = sessionkey
        cipher = Cipher(algorithms.AES(key), modes.CBC(ciphertext[:16]))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = self.unpad((plaintext[16:]).decode("utf-8"))
        return plaintext

    def encryptTextECB(self, plaintext, sessionkey):
        key = sessionkey
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        encryptor = cipher.encryptor()
        padded_data = self.pad(plaintext.encode("utf-8"), 16)
        log.info(plaintext.encode("utf-8"))
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext

    def decryptTextECB(self, ciphertext, sessionkey):
        key = sessionkey
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = self.unpad((plaintext).decode("utf-8"))
        return plaintext

    def findSessionKey(self, receiverStr):
        for e in self.otherClients:
            if str(e) == receiverStr:
                return e
        return None

    def pad(self, str, mul):
        currLen = len(str)
        neededBytes = (int(currLen / mul) + 1) * mul - currLen
        for i in range(neededBytes):
            str += b"1"
        log.info(neededBytes)
        log.info(str)
        return str

    def unpad(self, str):
        return str.split("\n")[0]
