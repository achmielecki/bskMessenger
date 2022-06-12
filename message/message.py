from enum import Enum


class MessageType(Enum):
    TEXT = 1
    FILE = 2
    SESSION = 3
    KEY = 4


class MessageEncryption(Enum):
    ECB = 1
    CBC = 2


class Message:
    def __init__(self, sender, type, content=None, receiver=None, encryption=None, part=None, parts=None, fExtension=None):
        self.sender = sender
        self.receiver = receiver
        self.content = content
        self.type = type
        self.encryption = encryption
        self.part = part
        self.parts = parts
        self.fileExtension = fExtension
