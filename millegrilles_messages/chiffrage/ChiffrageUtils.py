import multibase

from typing import Optional

from millegrilles_messages.messages.EnveloppeCertificat import EnveloppeCertificat
from millegrilles_messages.messages.Ed25519Utils import chiffrer_cle_ed25519


def generer_info_chiffrage(enveloppes: list[EnveloppeCertificat], cle_secrete: bytes, iv: bytes, tag: Optional[bytes], public_peer: Optional[bytes] = None):
    if len(enveloppes) == 0:
        raise ValueError("Aucuns certificats fournis")

    iv_str = multibase.encode('base64', iv).decode('utf-8')
    if tag is not None:
        tag_str = multibase.encode('base64', tag).decode('utf-8')
    else:
        tag_str = None

    if public_peer is not None:
        cle = multibase.encode('base64', tag).decode('utf-8')
    else:
        cle = None

    cles = dict()
    partition = None

    for enveloppe in enveloppes:
        cle_asym, fingerprint = chiffrage_asymmetrique(enveloppe, cle_secrete)
        cles[fingerprint] = cle_asym

        if enveloppe.is_root_ca is True and cle is None:
            cle = cle_asym
        else:
            # Selectionner une partition au hasard (si plus d'une cle de maitre des cles)
            partition = fingerprint

    info = {
        'iv': iv_str,
        'cles': cles,
    }

    if tag_str is not None:
        info['tag'] = tag_str

    if cle is not None:
        info['cle'] = cle

    if partition is not None:
        info['partition'] = partition

    return info


def chiffrage_asymmetrique(enveloppe: EnveloppeCertificat, cle_secrete):
    cle_asym = chiffrer_cle_ed25519(enveloppe, cle_secrete)
    fingerprint = enveloppe.fingerprint
    return cle_asym, fingerprint
