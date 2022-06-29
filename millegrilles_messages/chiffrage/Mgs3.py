import multibase

from typing import Optional, Union

from Crypto.Cipher import ChaCha20_Poly1305
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from millegrilles_messages.messages.EnveloppeCertificat import EnveloppeCertificat
from millegrilles_messages.messages.Hachage import hacher_to_digest
from millegrilles_messages.chiffrage.ChiffrageUtils import generer_info_chiffrage


class CipherMgs3:

    def __init__(self, public_key: X25519PublicKey, header: Optional[bytes] = None):
        self.__cle_secrete: Optional[bytes] = None
        self.__tag: Optional[bytes] = None
        self.__public_peer_x25519: Optional[bytes] = None

        self.__cipher = self.__generer_cipher(public_key)

        if header is not None:
            self.__cipher.update(header)

    def __generer_cipher(self, public_key: X25519PublicKey):
        """
        Generer la cle secrete a partir d'une cle publique
        """
        # Generer cle peer
        key_x25519 = X25519PrivateKey.generate()
        self.__public_peer_x25519 = key_x25519.public_key()

        # Extraire la cle secrete avec exchange
        cle_handshake = key_x25519.exchange(public_key)

        # Hacher avec blake2s-256
        self.__cle_secrete = hacher_to_digest(cle_handshake, 'blake2s-256')

        # Creer cipher (inclus nonce)
        cipher = ChaCha20_Poly1305.new(key=self.__cle_secrete)

        return cipher

    @property
    def nonce(self) -> bytes:
        return self.__cipher.nonce

    def update(self, data: bytes) -> bytes:
        return self.__cipher.encrypt(data)

    def finalize(self) -> bytes:
        if self.__tag is not None:
            raise Exception('Already finalized')

        self.__tag = self.__cipher.digest()

        return self.__tag

    def get_info_dechiffrage(self, enveloppes: list[EnveloppeCertificat]) -> dict:
        return generer_info_chiffrage(enveloppes, self.__cle_secrete, self.nonce, self.__tag)


class DecipherMgs3:

    def __init__(self, cle_secrete: bytes, nonce: Union[bytes, str], tag: Union[bytes, str], header: Optional[bytes] = None):

        if tag is not None:
            if isinstance(tag, str):
                self.__tag = multibase.decode(tag)
            elif isinstance(tag, bytes):
                self.__tag = tag
            else:
                raise TypeError('type tag non supporte (valides: str, bytes)')

        if isinstance(nonce, str):
            nonce = multibase.decode(nonce)
        elif isinstance(nonce, bytes):
            pass
        else:
            raise TypeError('type nonce non supporte (valides : str, bytes)')

        self.__decipher = ChaCha20_Poly1305.new(key=cle_secrete, nonce=nonce)

        if header is not None:
            self.__decipher.update(header)

    def update(self, data: bytes) -> bytes:
        return self.__decipher.decrypt(data)

    def finalize(self, tag: Optional[bytes] = None):
        if tag is None:
            tag = self.__tag
        self.__decipher.verify(tag)
