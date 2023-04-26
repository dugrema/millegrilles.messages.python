import multibase

from typing import Optional, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PublicFormat, PrivateFormat, \
    BestAvailableEncryption, NoEncryption
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from nacl.signing import SigningKey

from millegrilles_messages.messages.EnveloppeCertificat import EnveloppeCertificat
from millegrilles_messages.messages.Ed25519Utils import chiffrer_cle_ed25519, dechiffrer_cle_ed25519


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
    def from_files(path_key, path_certificat, path_password=None, password=None):
        with open(path_key, 'rb') as fichier:
            cle = fichier.read()
        with open(path_certificat, 'rb') as fichier:
            cert = fichier.read()

        if path_password is not None:
            with open(path_password, 'rb') as fichier:
                password = fichier.read()

        return CleCertificat.from_pems(cle, cert, password)

    def cle_correspondent(self):
        # Determiner format
        if self.is_rsa():
            public1 = self.private_key.public_key().public_numbers()
            public2 = self.enveloppe.certificat.public_key().public_numbers()

            n1 = public1.n
            n2 = public2.n

            return n1 == n2
        elif self.is_ed25519():
            if self.__private_key is not None and self.__enveloppe is not None:
                public1_bytes = self.__private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                public2_bytes = self.__enveloppe.get_public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                return public1_bytes == public2_bytes

        else:
            raise ValueError('Type de cle non supporte')

        return False

    def chiffrage_asymmetrique(self, cle_secrete):
        cle_asym = chiffrer_cle_ed25519(self.__enveloppe, cle_secrete)
        fingerprint = self.fingerprint
        return cle_asym, fingerprint

    def dechiffrage_asymmetrique(self, cle_chiffree: Union[bytes, str]):
        if isinstance(cle_chiffree, str):
            cle_chiffree = multibase.decode(cle_chiffree)
        return dechiffrer_cle_ed25519(self, cle_chiffree)

    def signer(self, message_bytes: bytes):
        signature = self.__private_key.sign(message_bytes)
        return signature

    def is_rsa(self):
        return self.enveloppe.is_rsa()

    def is_ed25519(self):
        return self.enveloppe.is_ed25519()

    @property
    def private_key(self):
        return self.__private_key

    @property
    def enveloppe(self) -> EnveloppeCertificat:
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

    def __str__(self):
        return 'CleCertificat %s (CN=%s)' % (self.fingerprint, self.enveloppe.subject_common_name)
