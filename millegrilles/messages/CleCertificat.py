from typing import Optional, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PublicFormat, PrivateFormat, \
    BestAvailableEncryption, NoEncryption
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from nacl.signing import SigningKey

from millegrilles.messages.EnveloppeCertificat import EnveloppeCertificat
from millegrilles.messages.Ed25519Utils import chiffrer_cle_ed25519


class CleCertificat:

    def __init__(self, private_key, enveloppe: EnveloppeCertificat):
        self.__private_key = private_key
        self.__enveloppe = enveloppe

    @staticmethod
    def from_pems(pem_key: Union[str, bytes], pem_certificat: Union[str, bytes], password: Union[str, bytes] = None):
        if isinstance(pem_key, str):
            pem_key = pem_key.encode('utf-8')

        if isinstance(password, str):
            password = password.encode('utf-8')

        private_key = load_pem_private_key(
            pem_key,
            password=password,
            backend=default_backend()
        )

        enveloppe = EnveloppeCertificat.from_pem(pem_certificat)

        return CleCertificat(private_key, enveloppe)

    @staticmethod
    def from_files(path_key, path_certificat, password=None):
        with open(path_key, 'rb') as fichier:
            cle = fichier.read()
        with open(path_certificat, 'rb') as fichier:
            cert = fichier.read()

        return CleCertificat.from_pems(cle, cert, password)

    def cle_correspondent(self):
        if self.__private_key is not None and self.__enveloppe is not None:
            public1_bytes = self.__private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            public2_bytes = self.__enveloppe.get_public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            return public1_bytes == public2_bytes

        return False

    def chiffrage_asymmetrique(self, cle_secrete):
        cle_asym = chiffrer_cle_ed25519(self, cle_secrete)
        fingerprint = self.fingerprint
        return cle_asym, fingerprint

    def signer(self, message_bytes: bytes):
        signature = self.__private_key.sign(message_bytes)
        return signature

    @property
    def enveloppe(self):
        return self.__enveloppe

    @property
    def get_roles(self):
        return self.__enveloppe.get_roles

    @property
    def get_exchanges(self):
        return self.__enveloppe.get_exchanges

    @property
    def get_domaines(self):
        return self.__enveloppe.get_domaines

    @property
    def get_user_id(self) -> str:
        return self.__enveloppe.get_user_id

    @property
    def fingerprint(self) -> str:
        return self.__enveloppe.fingerprint

    def private_key_bytes(self, password: Optional[Union[str, bytes]] = None) -> bytes:

        if password is not None:
            if isinstance(password, str):
                password = password.encode('utf-8')
            cle_privee_bytes = self.__private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8,
                                                                BestAvailableEncryption(password))
        else:
            cle_privee_bytes = self.__private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

        return cle_privee_bytes

    def get_private_x25519(self) -> X25519PrivateKey:
        if self.__private_key is not None:
            private_key = self.__private_key
        else:
            raise Exception("Cle privee non disponible")

        cle_private_bytes = private_key.private_bytes(encoding=Encoding.Raw, format=PrivateFormat.Raw,
                                                      encryption_algorithm=NoEncryption())

        cle_nacl_signingkey = SigningKey(cle_private_bytes)
        cle_x25519_prive = cle_nacl_signingkey.to_curve25519_private_key()
        x25519_private_key = X25519PrivateKey.from_private_bytes(cle_x25519_prive.encode())

        return x25519_private_key
