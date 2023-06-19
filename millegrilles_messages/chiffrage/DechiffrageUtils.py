import multibase
import json

from millegrilles_messages.messages.CleCertificat import CleCertificat
from millegrilles_messages.chiffrage.Mgs4 import DecipherMgs4


def dechiffrer_document(clecert: CleCertificat, cle_secrete: str, document_chiffre: dict):
    decipher = get_decipher(clecert, cle_secrete, document_chiffre)

    contenu_chiffre = document_chiffre['data_chiffre']
    if isinstance(contenu_chiffre, str):
        contenu_chiffre = multibase.decode(contenu_chiffre)

    contenu_dechiffre = decipher.update(contenu_chiffre)
    contenu_dechiffre += decipher.finalize()

    contenu_json = json.loads(contenu_dechiffre)

    return contenu_json


def get_decipher(clecert: CleCertificat, cle_secrete: str, document_chiffre: dict):
    doc_chiffre_info = {'cle': cle_secrete}
    doc_chiffre_info.update(document_chiffre)

    format_chiffrage = document_chiffre['format']
    if format_chiffrage == 'mgs4':
        decipher = DecipherMgs4.from_info(clecert, doc_chiffre_info)
    else:
        raise Exception("Format de chiffrage %s non supporte" % format_chiffrage)

    return decipher
