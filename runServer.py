import logging
from config import *
from server.server import Server

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger().setLevel(logging.DEBUG)
    log = logging.getLogger(__name__)
    log.info("________BSK MESSENGER SERVER________")
    server = Server(localPort, localHost)
