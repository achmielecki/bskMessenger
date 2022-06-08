from enum import Enum


class MessageType(Enum):
    TEXT = 'TEXT'
    FILE = 'FILE'


class Message:
    def __init__(self, sender, type, content=None, encryption=None, part=None, parts=None, fExtension=None):
        self.sender = sender
        self.content = content
        self.type = type
        self.encryption = encryption
        self.part = part
        self.parts = parts
        self.fileExtension = fExtension
