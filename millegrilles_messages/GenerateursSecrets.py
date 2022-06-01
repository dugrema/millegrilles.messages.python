import logging

from cryptography.hazmat.primitives import serialization, asymmetric
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class GenerateurRsa:

    def __init__(self):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def generer_keypair(self, size=2048):
        self.__logger.debug("Generer keypair")
        keypair = asymmetric.rsa.generate_private_key(
            public_exponent=65537,
            key_size=size,
        )

        return keypair

    def generer_private_openssh(self) -> bytes:
        keypair = self.generer_keypair()
        private_bytes = keypair.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()
        )
        return private_bytes


class GenerateurEd25519:

    def __init__(self):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def generer_keypair(self):
        self.__logger.debug("Generer keypair")
        keypair = Ed25519PrivateKey.generate()

        return keypair

    def generer_private_openssh(self) -> bytes:
        keypair = self.generer_keypair()
        private_bytes = keypair.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()
        )
        return private_bytes
