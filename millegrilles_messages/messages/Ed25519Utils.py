import multibase

from typing import Union

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization

from millegrilles_messages.messages.Hachage import hacher_to_digest


def chiffrer_cle_ed25519(enveloppe, cle_secrete: bytes) -> str:
    public_key: X25519PublicKey = enveloppe.get_public_x25519()

    # Generer peer pour chiffrer la cle
    key_x25519 = X25519PrivateKey.generate()

    # Extraire la cle secrete avec exchange
    cle_handshake = key_x25519.exchange(public_key)
    # Hacher avec blake2s-256
    password = hacher_to_digest(cle_handshake, 'blake2s-256')

    # Deriver le nonce a partir de la cle publique
    key_x25519_public_bytes = key_x25519.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    nonce = hacher_to_digest(key_x25519_public_bytes, 'blake2s-256')[0:12]

    # Chiffrer la cle secrete avec chacha20poly1305 (one pass)
    chacha = ChaCha20Poly1305(password)
    cyphertext_tag = chacha.encrypt(nonce, cle_secrete, None)

    cle_complete = key_x25519_public_bytes + cyphertext_tag
    cle_str = multibase.encode('base64', cle_complete).decode('utf-8')[1:]  # Retirer 'm' multibase

    return cle_str


def dechiffrer_cle_ed25519(enveloppe, cle_secrete: Union[bytes, str]) -> str:
    private_key: X25519PrivateKey = enveloppe.get_private_x25519()

    if isinstance(cle_secrete, str):
        # cle_secrete_bytes = multibase.decode(cle_secrete.encode('utf-8'))
        cle_secrete_bytes = multibase.decode(cle_secrete)
    else:
        cle_secrete_bytes = cle_secrete

    x25519_public_key = X25519PublicKey.from_public_bytes(cle_secrete_bytes[0:32])
    cle_chiffree_tag = cle_secrete_bytes[32:]

    # Extraire la cle secrete avec exchange
    cle_handshake = private_key.exchange(x25519_public_key)
    # Hacher avec blake2s-256
    password = hacher_to_digest(cle_handshake, 'blake2s-256')

    if len(cle_secrete_bytes) == 32:
        # Le password est la cle derivee secrete du message (chiffree avec la cle de millegrille)
        # if isinstance(password, bytes):
        #     password = password.decode('utf-8')
        return password

    # Deriver le nonce a partir de la cle publique
    nonce = hacher_to_digest(cle_secrete_bytes[0:32], 'blake2s-256')[0:12]

    # Chiffrer la cle secrete avec chacha20poly1305 (one pass)
    chacha = ChaCha20Poly1305(password)
    password_dechiffre = chacha.decrypt(nonce, cle_chiffree_tag, None)

    return password_dechiffre
