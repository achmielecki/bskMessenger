from enum import Enum


class MessageTypes(Enum):
    TEXT = 'TEXT'
    FILE = 'FILE'


class Message:
    def __init__(self, type, content=None, encryption=None, part=None, parts=None):
        self.content = content
        self.type = type
        self.encryption = encryption
        self.part = part
        self.parts = parts
