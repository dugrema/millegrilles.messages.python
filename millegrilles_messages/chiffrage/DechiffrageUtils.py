import binascii
import gzip
import json
import zlib

import multibase

from typing import Union

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


def dechiffrer_bytes_secrete(cle_secrete: bytes, document_chiffre: dict) -> bytes:
    decipher = get_decipher_cle_secrete(cle_secrete, document_chiffre)

    try:
        # Try to get explicit base64 (with padding) field
        contenu_chiffre = binascii.a2b_base64(document_chiffre['ciphertext_base64'])
    except KeyError:
        # Detect format
        contenu_chiffre = document_chiffre['data_chiffre']
        if isinstance(contenu_chiffre, str):
            if document_chiffre.get('nonce'):
                if contenu_chiffre.endswith('='):
                    contenu_chiffre = binascii.a2b_base64(contenu_chiffre)
                else:
                    # Nouveau format, ajouter 'm' pour multibase
                    contenu_chiffre = 'm' + contenu_chiffre
                    contenu_chiffre = multibase.decode(contenu_chiffre)
            else:
                contenu_chiffre = multibase.decode(contenu_chiffre)

    contenu_dechiffre = decipher.update(contenu_chiffre)
    contenu_dechiffre += decipher.finalize()

    try:
        compression = document_chiffre['compression']
        if compression == 'deflate':
            contenu_dechiffre = zlib.decompress(contenu_dechiffre)
        elif compression in ['gz', 'gzip']:
            contenu_dechiffre = gzip.decompress(contenu_dechiffre)
        else:
            raise Exception('Unsupported compression %s' % compression)
    except KeyError:
        pass

    return contenu_dechiffre


def dechiffrer_document_secrete(cle_secrete: bytes, document_chiffre: dict):
    contenu_dechiffre = dechiffrer_bytes_secrete(cle_secrete, document_chiffre)
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
            nonce = multibase.decode('m' + info_dechiffrage['nonce'])
        except KeyError:
            # Ancien format
            nonce = multibase.decode(info_dechiffrage['header'])
        decipher = DecipherMgs4(cle_secrete, nonce)
    else:
        raise Exception("Format de chiffrage %s non supporte" % format_chiffrage)

    return decipher


def dechiffrer_reponse(cle: Union[CleCertificat, bytes], message: dict) -> dict:
    dechiffrage = message['dechiffrage']
    format_chiffrage = dechiffrage['format']
    if format_chiffrage == 'mgs4':
        if isinstance(cle, CleCertificat):
            decipher = DecipherMgs4.from_info(cle, dechiffrage)
        elif isinstance(cle, bytes):
            decipher = DecipherMgs4.from_info_with_key(cle, dechiffrage)
        else:
            raise TypeError('Mayvais type pour la cle')
    else:
        raise Exception("Format de chiffrage %s non supporte" % format_chiffrage)

    output_bytes = multibase.decode('m' + message['contenu'])
    output_bytes = decipher.update(output_bytes)
    output_bytes += decipher.finalize()
    output_bytes = gzip.decompress(output_bytes).decode('utf-8')

    message_dict = json.loads(output_bytes)
    return message_dict
