import binascii
from cryptography.hazmat.primitives import serialization

from millegrilles_messages.chiffrage.ChiffrageUtils import chiffrage_asymmetrique

from millegrilles_messages.chiffrage.Mgs4 import generer_cle_secrete
from millegrilles_messages.chiffrage.SignatureDomaines import SignatureDomaines
from millegrilles_messages.messages.EnveloppeCertificat import EnveloppeCertificat


class EncryptionKey:

    def __init__(self, secret_key: bytes, domain_signature: SignatureDomaines):
        self.__secret_key = secret_key
        self.__key_id = domain_signature.get_cle_ref()
        self.__signature = domain_signature

    def encrypt_secret_key(self, for_certificates: list[EnveloppeCertificat]) -> dict[str, str]:
        """ Encrypts the secret key for given certificates """
        result = dict()
        for cert in for_certificates:
            encrypted_key, fingerprint = chiffrage_asymmetrique(cert, self.__secret_key)
            result[fingerprint] = encrypted_key
        return result

    def produce_keymaster_content(self, for_certificates: list[EnveloppeCertificat]):
        """ Produces a new (unsigned) keymaster command """
        keys = self.encrypt_secret_key(for_certificates)
        return {
            'cles': keys,
            'signature': self.__signature.to_dict(),
        }

    @property
    def secret_key(self):
        return self.__secret_key

    @property
    def key_id(self):
        return self.__key_id


def generate_new_secret(ca: EnveloppeCertificat, domains: list[str]) -> EncryptionKey:
    public_peer_x25519, secret_key = generer_cle_secrete(ca.get_public_x25519())
    peer_bytes = public_peer_x25519.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    peer_base64 = binascii.b2a_base64(peer_bytes, newline=False).decode('utf-8').replace('=', '')
    domain_signature = SignatureDomaines.signer_domaines(secret_key, domains, peer_base64)
    return EncryptionKey(secret_key, domain_signature)
