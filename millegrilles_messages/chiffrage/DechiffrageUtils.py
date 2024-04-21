import gzip
import json
import multibase

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


def dechiffrer_document_secrete(cle_secrete: bytes, document_chiffre: dict):
    decipher = get_decipher_cle_secrete(cle_secrete, document_chiffre)

    contenu_chiffre = document_chiffre['data_chiffre']
    if isinstance(contenu_chiffre, str):
        if document_chiffre.get('nonce'):
            # Nouveau format, ajouter 'm' pour multibase
            contenu_chiffre = 'm' + contenu_chiffre
        contenu_chiffre = multibase.decode(contenu_chiffre)

    contenu_dechiffre = decipher.update(contenu_chiffre)
    contenu_dechiffre += decipher.finalize()

    contenu_json = json.loads(contenu_dechiffre)

    return contenu_json


def get_decipher(clecert: CleCertificat, cle_secrete: str, document_chiffre: dict):
    doc_chiffre_info = document_chiffre.copy()
    doc_chiffre_info['cle'] = cle_secrete

    format_chiffrage = document_chiffre['format']
    if format_chiffrage == 'mgs4':
        decipher = DecipherMgs4.from_info(clecert, doc_chiffre_info)
    else:
        raise Exception("Format de chiffrage %s non supporte" % format_chiffrage)

    return decipher


def get_decipher_cle_secrete(cle_secrete: bytes, info_dechiffrage):
    format_chiffrage = info_dechiffrage['format']
    if format_chiffrage == 'mgs4':
        try:
            nonce = 'm' + info_dechiffrage['nonce']
        except KeyError:
            # Ancien format
            nonce = info_dechiffrage['header']
        decipher = DecipherMgs4(cle_secrete, nonce)
    else:
        raise Exception("Format de chiffrage %s non supporte" % format_chiffrage)

    return decipher


def dechiffrer_reponse(clecert: CleCertificat, message: dict) -> dict:
    dechiffrage = message['dechiffrage']
    format_chiffrage = dechiffrage['format']
    if format_chiffrage == 'mgs4':
        decipher = DecipherMgs4.from_info(clecert, dechiffrage)
    else:
        raise Exception("Format de chiffrage %s non supporte" % format_chiffrage)

    output_bytes = multibase.decode('m' + message['contenu'])
    output_bytes = decipher.update(output_bytes)
    output_bytes += decipher.finalize()
    output_bytes = gzip.decompress(output_bytes).decode('utf-8')

    message_dict = json.loads(output_bytes)
    return message_dict
