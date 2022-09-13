import multibase

from typing import Optional, Union

from millegrilles_messages.messages.EnveloppeCertificat import EnveloppeCertificat
from millegrilles_messages.messages.Ed25519Utils import chiffrer_cle_ed25519


def generer_info_chiffrage(cle_secrete: bytes, iv: Optional[bytes], tag: Optional[bytes], header: Optional[bytes],
                           hachage: Optional[Union[bytes, str]],
                           enveloppes: Optional[list[EnveloppeCertificat]] = None, public_peer: Optional[bytes] = None):

    if (enveloppes is None or len(enveloppes) == 0) and public_peer is None:
        raise ValueError("Aucuns certificats/public_peer fournis")

    if iv is not None:
        iv_str = multibase.encode('base64', iv).decode('utf-8')
    else:
        iv_str = None
    if tag is not None:
        tag_str = multibase.encode('base64', tag).decode('utf-8')
    else:
        tag_str = None
    if header is not None:
        header_str = multibase.encode('base64', header).decode('utf-8')
    else:
        header_str = None

    if public_peer is not None:
        cle = multibase.encode('base64', public_peer).decode('utf-8')
    else:
        cle = None

    if hachage is not None:
        if isinstance(hachage, bytes):
            hachage = multibase.encode('base64', hachage).decode('utf-8')
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
