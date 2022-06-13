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
from client.views.progressFrame import Progressframe

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
        decryptedContent = ""
        if message.encryption == "CBC":
            decryptedContent = self.decryptTextCBC(message.content, self.sessionKeys[message.sender], paddedBytes=message.padded)
        elif message.encryption == "ECB":
            decryptedContent = self.decryptTextECB(message.content, self.sessionKeys[message.sender], paddedBytes=message.padded)
        self.output.insert(END, f"\n [{message.sender[0]}:{message.sender[1]}] {decryptedContent}")
        self.output.see('end')

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
        messages = []
        lastPart = None
        msg = message
        while len(messages) != message.parts:
            if msg.encryption is "OFB":
                decryptedMsg, lastPart = self.decryptPartOFB(msg.content, lastPart, self.sessionKeys[message.sender], message.padded)
            else:
                decryptedMsg, lastPart = self.decryptPartCBC(msg.content, lastPart, self.sessionKeys[message.sender], message.padded)
            log.info(f"Received {1 + msg.part} of {msg.parts}")
            log.info(f"Received message {decryptedMsg}")
            messages.append(decryptedMsg)
            if len(messages) != message.parts:
                msg = self.getNextMessage()
        with open(f'downloaded.txt', "w+b") as file:
            file.write(b''.join(messages))
        os.rename('downloaded.txt', f'downloaded{message.fileExtension}')
        log.info(f"Wrote {len(messages)} parts")

    def sendTextMessage(self, content, receiver, encryptionMode):
        log.info('TypedEnter')
        if self.isConnectionActive:
            log.info('Sending text message')
            encryptedContent = ""
            paddedBytes = 0
            if(encryptionMode == "CBC"):
                encryptedContent, paddedBytes = self.encryptTextCBC(content, self.sessionKeys[self.findSessionKey(receiver)])
            elif encryptionMode == "ECB":
                encryptedContent, paddedBytes = self.encryptTextECB(content, self.sessionKeys[self.findSessionKey(receiver)])
            try:
                msg = Message(self.socket.getsockname(), MessageType.TEXT, encryptedContent, receiver, encryption=encryptionMode, padded=paddedBytes)
                self.sendMessage(msg)
            except ConnectionResetError as e:
                self.isConnectionActive = False

    def sendFile(self, filename, receiver, encryptionMode):
        max = 1024 * 50
        log.info('FileChosen')
        progress = Progressframe()
        if self.isConnectionActive:
            log.info('Sending file')
            fExtension = os.path.splitext(filename)[1]
            parts = math.ceil(os.path.getsize(filename) / max)
            lastPart = None
            with open(filename, 'r+b') as source:
                part = 0
                while True:
                    msg = Message(self.socket.getsockname(), MessageType.FILE, None, receiver, None, part, parts, fExtension)
                    data = source.read(max)
                    if encryptionMode is "OFB":
                        encryptedMsg, lastPart, paddedBytes = self.encryptPartOFB(data, lastPart, self.sessionKeys[self.findSessionKey(receiver)])
                    else:
                        encryptedMsg, lastPart, paddedBytes = self.encryptPartCBC(data, lastPart, self.sessionKeys[self.findSessionKey(receiver)])
                    msg.content = encryptedMsg
                    msg.padded = paddedBytes
                    msg.encryption = encryptionMode
                    self.sendMessage(msg)
                    progress.updateValue(1 + part, parts)
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

    def encryptTextCBC(self, plaintext, sessionkey, lastBlock=None):
        key = sessionkey
        if lastBlock is not None:
            iv = lastBlock
        else:
            iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        log.info(f"before encrypting sent {iv}")
        if lastBlock is not None:
            iv = b''
        encryptor = cipher.encryptor()
        if type(plaintext) is bytes:
            text = plaintext
        else:
            text = plaintext.encode("utf-8")
        padded_data, paddedBytes = self.pad(text, 16)
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        ciphertext = iv + ciphertext
        return ciphertext, paddedBytes

    def decryptTextCBC(self, ciphertext, sessionkey, lastBlock=None, encoded=True, paddedBytes=0):
        key = sessionkey
        if lastBlock is not None:
            iv = lastBlock
        else:
            iv = ciphertext[:16]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        if lastBlock is None:
            plaintext = plaintext[16:]
        if encoded:
            plaintext = plaintext.decode("utf-8")
        plaintext = self.unpad(plaintext, paddedBytes)
        log.info(f"decrypted {iv}")
        return plaintext

    def encryptTextECB(self, plaintext, sessionkey):
        key = sessionkey
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        encryptor = cipher.encryptor()
        padded_data, paddedBytes = self.pad(plaintext.encode("utf-8"), 16)
        log.info(plaintext.encode("utf-8"))
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext, paddedBytes

    def decryptTextECB(self, ciphertext, sessionkey, paddedBytes=0):
        key = sessionkey
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = self.unpad(plaintext.decode("utf-8"), paddedBytes)
        return plaintext

    def encryptTextOFB(self, plaintext, sessionkey, lastBlock=None):
        key = sessionkey
        if lastBlock is not None:
            iv = lastBlock
        else:
            iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.OFB(iv))
        log.info(f"before encrypting sent {iv}")
        if lastBlock is not None:
            iv = b''
        encryptor = cipher.encryptor()
        if type(plaintext) is bytes:
            text = plaintext
        else:
            text = plaintext.encode("utf-8")
        padded_data, paddedBytes = self.pad(text, 16)
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        ciphertext = iv + ciphertext
        return ciphertext, paddedBytes

    def decryptTextOFB(self, ciphertext, sessionkey, lastBlock=None, encoded=True, paddedBytes=0):
        key = sessionkey
        if lastBlock is not None:
            iv = lastBlock
        else:
            iv = ciphertext[:16]
        cipher = Cipher(algorithms.AES(key), modes.OFB(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        if lastBlock is None:
            plaintext = plaintext[16:]
        if encoded:
            plaintext = plaintext.decode("utf-8")
            plaintext = self.unpad(plaintext, paddedBytes)
        log.info(f"decrypted {iv}")
        return plaintext

    def encryptPartCBC(self, part, lastPart, sessionkey):
        encryptedPart, paddedBytes = self.encryptTextCBC(part, sessionkey, lastPart)
        lastPart = encryptedPart[-16:]
        return encryptedPart, lastPart, paddedBytes

    def decryptPartCBC(self, encryptedPart, lastPart, sessionkey, paddedBytes):
        lastBlock = encryptedPart[-16:]
        decryptedPart = self.decryptTextCBC(encryptedPart, sessionkey, lastPart, False, paddedBytes)
        return decryptedPart, lastBlock

    def encryptPartOFB(self, part, lastPart, sessionkey):
        encryptedPart, paddedBytes = self.encryptTextOFB(part, sessionkey, lastPart)
        lastPart = encryptedPart[-16:]
        return encryptedPart, lastPart, paddedBytes

    def decryptPartOFB(self, encryptedPart, lastPart, sessionkey, paddedBytes):
        lastBlock = encryptedPart[-16:]
        decryptedPart = self.decryptTextOFB(encryptedPart, sessionkey, lastPart, False, paddedBytes)
        return decryptedPart, lastBlock

    def findSessionKey(self, receiverStr):
        for e in self.otherClients:
            if str(e) == receiverStr:
                return e
        return None

    def pad(self, str, mul):
        currLen = len(str)
        neededBytes = (int(currLen / mul) + 1) * mul - currLen
        for i in range(neededBytes):
            str += b'1'
        return str, neededBytes

    def unpad(self, str, paddedBytes):
        return str[:-paddedBytes]
