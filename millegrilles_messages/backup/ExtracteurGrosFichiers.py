# Extracteur de GrosFichiers
import os

import aiohttp
import asyncio
import logging
import json
import ssl

from os import path
from typing import Optional

from millegrilles_messages.backup.Configuration import ConfigurationExtracteurGrosFichiers
from millegrilles_messages.messages import Constantes

from millegrilles_messages.messages.MessagesThread import MessagesThread
from millegrilles_messages.messages.MessagesModule import RessourcesConsommation
from millegrilles_messages.messages.CleCertificat import CleCertificat

__logger = logging.getLogger(__name__)

CONST_CHUNK_SIZE = 64 * 1024
CONST_PATH_CHIFFRE = '/tmp/grosfichiers/chiffre'
CONST_PATH_DECHIFFRE = '/tmp/grosfichiers/dechiffre'


class ExtracteurGrosFichiers:

    def __init__(self, config: dict):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__config = ConfigurationExtracteurGrosFichiers()

        self.__messages_thread: Optional[MessagesThread] = None
        self.__demarrage_confirme: Optional[asyncio.Event()] = None
        self.__stop_event: Optional[asyncio.Event()] = None

        # Parse configuration environnement
        self.__config.parse_config(config)
        self.__clecert: Optional[CleCertificat] = None
        self.__ssl_context = None

    async def preparer(self):
        reply_res = RessourcesConsommation(self.traiter_reponse)
        self.__stop_event = asyncio.Event()
        self.__demarrage_confirme = asyncio.Event()
        messages_thread = MessagesThread(self.__stop_event)
        messages_thread.set_reply_ressources(reply_res)

        config = {
            'CERT_PEM': self.__config.cert_pem_path,
            'KEY_PEM': self.__config.key_pem_path,
            'CA_PEM': self.__config.ca_pem_path,
        }
        messages_thread.set_env_configuration(config)

        self.__messages_thread = messages_thread

    def preparer_dechiffrage(self):
        clecert = CleCertificat.from_files(self.__config.key_pem_path, self.__config.cert_pem_path)
        if not clecert.cle_correspondent():
            raise Exception("Fichiers Cle/Cert ne correspondent pas")

        self.__ssl_context = ssl.create_default_context(cafile=self.__config.ca_pem_path)
        self.__ssl_context.load_cert_chain(self.__config.cert_pem_path, self.__config.key_pem_path)

    async def run(self):
        self.__logger.info("ExtracteurGrosFichiers Run")
        await recuperer_fichiers(self.__config.url_consignation, self.__ssl_context)
        self.__logger.info("ExtracteurGrosFichiers Done")

    async def traiter_reponse(self, message, module_messages: MessagesThread):
        self.__logger.info("Message recu : %s" % json.dumps(message.parsed, indent=2))

        message_parsed = message.parsed
        # if message_parsed.get('ok') == True:
        #     self.__logger.info("Backup demarre")
        # else:
        #     self.__logger.warning("Erreur demarrage du backup : %s" % message_parsed.get('err'))
        #
        # self.__demarrage_confirme.set()


async def recuperer_fichiers(url_consignation: str, ssl_context):
    __logger.info("recuperer_fichiers Debut")

    os.makedirs(CONST_PATH_CHIFFRE, exist_ok=True)
    os.makedirs(CONST_PATH_DECHIFFRE, exist_ok=True)

    conn = aiohttp.TCPConnector(ssl_context=ssl_context)
    async with aiohttp.ClientSession(connector=conn) as session:
        await download_liste_fichiers(session, url_consignation)

    __logger.info("recuperer_fichiers Fin")


async def download_liste_fichiers(session, url_consignation: str):

    path_get_fichiers = url_consignation + path.join('/fichiers_transfert', 'backup', 'liste')
    __logger.debug("get_liste_fichiers Path %s" % path_get_fichiers)

    # Recuperer la liste de tous les fichiers en consignation
    async with session.get(path_get_fichiers) as resp:
        __logger.debug("Reponse status %d" % resp.status)

        async for line in resp.content:
            fuuid = line.strip().decode('utf-8')
            path_fuuid_local = path.join(CONST_PATH_CHIFFRE, fuuid)

            # Verifier si le fichier existe deja
            try:
                os.stat(path_fuuid_local)
                __logger.debug("Fichier existe deja : %s" % path_fuuid_local)
            except FileNotFoundError:
                path_fuuid = url_consignation + path.join('/fichiers_transfert', fuuid)
                __logger.debug("download_fichier Download fichier %s" % path_fuuid)

                async with session.get(path_fuuid) as resp:
                    __logger.debug("Reponse status fichier %s = %d" % (fuuid, resp.status))
                    with open(path_fuuid_local, 'wb') as fd:
                        async for chunk in resp.content.iter_chunked(CONST_CHUNK_SIZE):
                            fd.write(chunk)


async def main(ca: Optional[str]):
    config = dict()

    if ca is not None:
        config['CA_PEM'] = ca

    extracteur = ExtracteurGrosFichiers(config)
    extracteur.preparer_dechiffrage()
    await extracteur.run()
