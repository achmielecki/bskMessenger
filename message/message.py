from enum import Enum
from typing import Union


class MessageTypes(Enum):
    CONNECT = 'CONNECT'
    DISCONNECT = 'DISCONNECT'
    TEXT = 'TEXT'
    FILE = 'FILE'


class Message:
    def __init__(self, id: str, type: str, receiver_id: str = None,  msg: Union[str, bytes, int] = None,
                 encryption_mode: int = None, file_parts: int = None, extension: str = None) -> None:
        self.sender_id = id
        self.receiver_id = receiver_id
        self.msg = msg
        self.type = type
        self.encryption_mode = encryption_mode
        self.file_parts = file_parts
        self.extension = extension
