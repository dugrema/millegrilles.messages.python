import binascii
import json
import multibase

from typing import Optional
from cryptography.hazmat.primitives.asymmetric import ed25519
from millegrilles_messages.messages.Hachage import hacher_to_digest


class SignatureDomaines:

    def __init__(self):
        self.domaines: Optional[list] = None
        self.ca: Optional[str] = None
        self.signature: Optional[str] = None
        self.version: Optional[int] = None

    @staticmethod
    def signer_domaines(cle_secrete: bytes, domaines: list[str], cle_ca: Optional[str]):
        signature = SignatureDomaines()
        signature.ca = cle_ca
        signature.domaines = domaines

        domaines_bytes = json.dumps(domaines).encode('utf-8')
        hachage_domaines = hacher_to_digest(domaines_bytes, hashing_code='blake2s-256')

        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(cle_secrete)
        signature_value = private_key.sign(hachage_domaines)
        signature_str = multibase.encode('base64', signature_value).decode('utf-8')

        signature.signature = signature_str[1:]  # Encoder, retirer 'm' multibase pour format base64 no pad
        signature.version = 1

        return signature

    @staticmethod
    def from_dict(value: dict):
        signature = SignatureDomaines()
        signature.domaines = value['domaines']
        signature.signature = value['signature']
        signature.version = value['version']
        signature.ca = value.get('ca')

        return signature

    def verifier(self, cle_secrete: bytes):
        if self.version == 0:
            return  # Aucune verification possible sur version 0
        elif self.version != 1:
            raise ValueError("Version non supportee")

        domaines_bytes = json.dumps(self.domaines).encode('utf-8')
        hachage_domaines = hacher_to_digest(domaines_bytes, hashing_code='blake2s-256')

        signature: bytes = multibase.decode('m' + self.signature)
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(cle_secrete)
        public_key = private_key.public_key()
        public_key.verify(signature, hachage_domaines)

    def get_cle_ref(self) -> str:
        signature_bytes = multibase.decode('m' + self.signature)
        hachage_domaines = hacher_to_digest(signature_bytes, hashing_code='blake2s-256')
        print("Hachages domaines hex\n%s" % binascii.hexlify(hachage_domaines).decode('utf-8'))

        # Encoder en base58btc
        hachage_str = multibase.encode('base58btc', hachage_domaines).decode('utf-8')

        if hachage_domaines[0] == 0x0:
            # Hack - en Rust et Javascript, multibase base58btc insere la valeur '1' pour
            # un hachage qui commence par 0x0.
            hachage_str = 'z1' + hachage_str[1:]

        return hachage_str

    def to_dict(self):
        value = {
            'domaines': self.domaines,
            'signature': self.signature,
            'version': self.version,
        }
        if self.ca is not None:
            value['ca'] = self.ca

        return value

