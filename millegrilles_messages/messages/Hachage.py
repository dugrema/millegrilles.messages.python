"""
Module avec les fonctions de hachage utilisees dans MilleGrilles.

Inclus les conversions avec multihash et multibase
"""
import base64

import multibase
import multihash

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from multihash.constants import HASH_CODES
from typing import Union, Optional


class Hacheur:
    """
    Hacheur qui supporte verification de hachage de streams (via update).
    """

    def __init__(self, hashing_code: Union[int, str] = 'blake2b-512', encoding: str = 'base64'):
        """
        :param hashing_code: int ou str de l'algorithme de hachage, e.g. sha2-256, BLAKE2s-256
                             Voir multihash.constantes.HASH_TABLE pour valeurs supportees.
        :param encoding: Encoding du multibase, e.g. base58btc
                         Voir multibase.ENCODINGS pour valeurs supportees.
        """

        self.__encoding = encoding

        if isinstance(hashing_code, str):
            hashing_code = HASH_CODES[hashing_code]
        self.__hashing_code = hashing_code

        hashing_function = map_code_to_hashes(hashing_code)
        self.__hashing_context = hashes.Hash(hashing_function, backend=default_backend())

        self.__digest: Optional[bytes] = None

    def update(self, data: Union[str, bytes]):
        if isinstance(data, str):
            data = data.encode('utf-8')
        self.__hashing_context.update(data)

    def digest(self):
        """
        Calcule le digest
        :return: Digest en bytes
        """
        if self.__digest is None:
            self.__digest = self.__hashing_context.finalize()
            self.__hashing_context = None
        return self.__digest

    def finalize(self):
        """
        Calcule le digest et retourne le multibase encode
        :return: str Multibase encode
        """
        digest = self.digest()
        mh = multihash.encode(digest, self.__hashing_code)
        mb = multibase.encode(self.__encoding, mh)
        return mb.decode('utf-8')


class VerificateurHachage:

    def __init__(self, hachage_multibase: str):
        """
        :param hachage_multibase: Hachage a verifier
        """
        self.__hachage_multibase = hachage_multibase

        mb = multibase.decode(hachage_multibase)
        mh = multihash.decode(mb)
        self.__hachage_recu = mh.digest
        self.__hashing_code = mh.code

        hashing_function = map_code_to_hashes(self.__hashing_code)
        self.__hashing_context = hashes.Hash(hashing_function, backend=default_backend())

        self.__hachage_calcule: Optional[bytes] = None

    def update(self, data: Union[str, bytes]):
        if isinstance(data, str):
            data = data.encode('utf-8')
        self.__hashing_context.update(data)

    def digest(self) -> bytes:
        """
        Calcule le digest
        :return: Digest en bytes
        """
        if self.__hachage_calcule is None:
            self.__hachage_calcule = self.__hashing_context.finalize()
            self.__hashing_context = None
        return self.__hachage_calcule

    def verify(self) -> bool:
        """
        Calcule le digest
        :return: True si le hachage calcule correspond a celui fourni.
        :raises ErreurHachage: Si le digest calcule ne correspond pas au hachage fourni
        """
        hachage_calcule = self.digest()
        if hachage_calcule != self.__hachage_recu:
            recu = base64.b64encode(self.__hachage_recu).decode('utf-8')
            calcule = base64.b64encode(hachage_calcule).decode('utf-8')
            raise ErreurHachage("Hachage different : recu %s != calcule %s" % (recu, calcule))

        return True


def hacher_to_digest(valeur: Union[bytes, str], hashing_code: Union[int, str] = 'blake2b-512') -> bytes:
    """
    Calcule un hachage en format multibase
    :param valeur: Valeur a hacher
    :param hashing_code: int ou str de l'algorithme de hachage, e.g. sha2-256, BLAKE2s-256
                         Voir multihash.constantes.HASH_TABLE pour valeurs supportees.
    :return: bytes Digest calcule
    """

    if isinstance(hashing_code, str):
        hashing_code = HASH_CODES[hashing_code]

    hashing_function = map_code_to_hashes(hashing_code)
    context = hashes.Hash(hashing_function, backend=default_backend())

    if isinstance(valeur, str):
        valeur = valeur.encode('utf-8')
    elif isinstance(valeur, dict):
        # Serializer avec json
        pass

    context.update(valeur)
    digest = context.finalize()

    return digest


def hacher(valeur: Union[bytes, str], hashing_code: Union[int, str] = 'sha2-512', encoding: str = 'base58btc') -> str:
    """
    Calcule le hachage et retourne la valeur multibase
    :param valeur: Valeur a hacher
    :param hashing_code: int ou str de l'algorithme de hachage, e.g. sha2-256, BLAKE2s-256
                         Voir multihash.constantes.HASH_TABLE pour valeurs supportees.
    :param encoding: Encoding du multibase, e.g. base58btc
                     Voir multibase.ENCODINGS pour valeurs supportees.
    :return:
    """
    digest = hacher_to_digest(valeur, hashing_code)
    if isinstance(hashing_code, str):
        hashing_code = HASH_CODES[hashing_code]
    mh = multihash.encode(digest, hashing_code)
    mb = multibase.encode(encoding, mh)
    return mb.decode('utf-8')


def verifier_hachage(hachage_multibase: str, valeur: Union[bytes, str]) -> bool:
    """

    :param hachage_multibase: Hachage a verifier
    :param valeur: Valeur a hacher pour la verification
    :return: True si le hachage calcule correspond a celui fourni.
    :raises ErreurHachage: Si le digest calcule ne correspond pas au hachage fourni
    """
    mb = multibase.decode(hachage_multibase)
    mh = multihash.decode(mb)
    hachage_recu = mh.digest
    code = mh.code

    # Verifier hachage
    hachage_calcule = hacher_to_digest(valeur, code)
    if hachage_recu != hachage_calcule:
        raise ErreurHachage("Hachage different")

    return True


def map_code_to_hashes(code: int) -> hashes.HashAlgorithm:
    """
    Fait correspondre un code multihash a un algorithme de hachage Cryptography
    :param code: Code d'algorithme multihash
    :return: HashAlgorithm correspondant au code multihash
    """

    if code == 0x12:
        return hashes.SHA256()
    if code == 0x13:
        return hashes.SHA512()
    if code == 0xb240:
        return hashes.BLAKE2b(64)
    if code == 0xb260:
        return hashes.BLAKE2s(32)
    raise ValueError("Hachage non supporte : %d", code)


class ErreurHachage(Exception):
    pass
