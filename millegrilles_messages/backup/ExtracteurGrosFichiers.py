# Extracteur de GrosFichiers
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
    fichiers = await get_liste_fichiers(url_consignation, ssl_context)
    for fuuid in fichiers:
        await download_fichier(fuuid)
    __logger.info("recuperer_fichiers Fin")


async def get_liste_fichiers(url_consignation: str, ssl_context) -> list:

    path_get_fichiers = url_consignation + path.join('/fichiers', 'liste')

    conn = aiohttp.TCPConnector(ssl_context=ssl_context)
    async with aiohttp.ClientSession(connector=conn) as session:
        async with session.get(path_get_fichiers) as resp:
            text_response = await resp.text()

    print("Reponse %s" % text_response)

    fichiers = []
    return fichiers


async def download_fichier(fuuid: str):
    pass


async def main(ca: Optional[str]):
    config = dict()

    if ca is not None:
        config['CA_PEM'] = ca

    extracteur = ExtracteurGrosFichiers(config)
    extracteur.preparer_dechiffrage()
    await extracteur.run()
