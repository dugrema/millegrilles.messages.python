import multibase

from typing import Optional, Union
from cryptography.hazmat.primitives.asymmetric import ed25519

from millegrilles_messages.messages.Hachage import hacher_to_digest
from millegrilles_messages.messages.EnveloppeCertificat import EnveloppeCertificat
from millegrilles_messages.messages.Ed25519Utils import chiffrer_cle_ed25519
from millegrilles_messages.messages.FormatteurMessages import preparer_message_bytes


class ParametresChiffrage:

    def __init__(self):
        pass

    def get_chiffreur(self):
        pass

    def generer(self, format_chiffrage: Optional[str]):
        """
        Genere des nouveaux parametres de chiffrage
        @param format_chiffrage: Format de chiffrage, e.g. mgs4
        :return:
        """
        if format_chiffrage is not None and format_chiffrage not in ['mgs4']:
            raise ValueError('format de chiffrage non supporte')

        pass


def generer_info_chiffrage(cle_secrete: bytes, iv: Optional[bytes], tag: Optional[bytes], header: Optional[bytes],
                           hachage: Optional[Union[bytes, str]],
                           enveloppes: Optional[list[EnveloppeCertificat]] = None, public_peer: Optional[bytes] = None):

    if (enveloppes is None or len(enveloppes) == 0) and public_peer is None:
        raise ValueError("Aucuns certificats/public_peer fournis")

    if iv is not None:
        iv_str = multibase.encode('base64', iv).decode('utf-8')[1:]
    else:
        iv_str = None
    if tag is not None:
        tag_str = multibase.encode('base64', tag).decode('utf-8')[1:]
    else:
        tag_str = None
    if header is not None:
        header_str = multibase.encode('base64', header).decode('utf-8')[1:]
    else:
        header_str = None

    if public_peer is not None:
        cle = multibase.encode('base64', public_peer).decode('utf-8')[1:]
    else:
        cle = None

    if hachage is not None:
        if isinstance(hachage, bytes):
            hachage = multibase.encode('base64', hachage).decode('utf-8')[1:]
        elif isinstance(hachage, str):
            pass
        else:
            raise TypeError('hachage type invalide (doit etre bytes ou str)')
    else:
        hachage = None

    cles = dict()
    partition = None

    try:
        for enveloppe in enveloppes:
            cle_asym, fingerprint = chiffrage_asymmetrique(enveloppe, cle_secrete)
            cles[fingerprint] = cle_asym

            if enveloppe.is_root_ca is True:
                if cle is None:
                    cle = cle_asym
                cles[fingerprint] = cle  # Remplacer cle par version courte (public peer) au besoin
            else:
                # Selectionner une partition au hasard (si plus d'une cle de maitre des cles)
                partition = fingerprint
    except TypeError:
        pass  # Aucunes enveloppes

    info = dict()

    if len(cles) > 0:
        info['cles'] = cles

    if iv_str is not None:
        info['iv'] = iv_str

    if tag_str is not None:
        info['tag'] = tag_str

    if header_str is not None:
        info['header'] = header_str

    if cle is not None:
        info['cle'] = cle

    if partition is not None:
        info['partition'] = partition

    if hachage is not None:
        info['hachage_bytes'] = hachage

    return info


def chiffrage_asymmetrique(enveloppe: EnveloppeCertificat, cle_secrete):
    cle_asym = chiffrer_cle_ed25519(enveloppe, cle_secrete)
    fingerprint = enveloppe.fingerprint
    return cle_asym, fingerprint


def generer_signature_identite_cle(password: bytes, domaine: str, identificateurs_document: dict, hachage_bytes: str) -> str:
    hachage_cle = hacher_to_digest(password, hashing_code='blake2s-256')
    identite_cle = {
        'domaine': domaine,
        'identificateurs_document': identificateurs_document,
        'hachage_bytes': hachage_bytes
    }
    identite_bytes = preparer_message_bytes(identite_cle)
    hachage_identite = hacher_to_digest(identite_bytes, hashing_code='blake2b-512')

    VERSION_SIGNATURE = 0x2

    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(hachage_cle)
    signature = private_key.sign(hachage_identite)
    signature = list(signature)
    signature.insert(0, VERSION_SIGNATURE)
    signature = bytes(signature)
    signature = multibase.encode('base64', signature).decode('utf-8')[1:]

    return signature

# async function signerIdentiteCle(password, domaine, identificateurs_document, hachage_bytes) {
#   // Creer l'identitie de cle (permet de determiner qui a le droit de recevoir un dechiffrage)
#   // Signer l'itentite avec la cle secrete - prouve que l'emetteur de cette commande possede la cle secrete
#   const identiteCle = { domaine, identificateurs_document, hachage_bytes }
#   // if(userId) identiteCle.user_id = userId
#
#   const clePriveeEd25519 = await hacher(password, {encoding: 'bytes', hashingCode: 'blake2s-256'})
#
#   const cleEd25519 = ed25519.generateKeyPair({seed: clePriveeEd25519})
#   const signateur = new SignateurMessageEd25519(cleEd25519.privateKey)
#   await signateur.ready
#   const signatureIdentiteCle = await signateur.signer(identiteCle)
#
#   return signatureIdentiteCle
# }

