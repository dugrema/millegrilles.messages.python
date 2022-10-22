# Extracteur de GrosFichiers
import asyncio
import logging
import json

from typing import Optional

from millegrilles_messages.backup.Configuration import ConfigurationExtracteurGrosFichiers
from millegrilles_messages.messages import Constantes

from millegrilles_messages.messages.MessagesThread import MessagesThread
from millegrilles_messages.messages.MessagesModule import RessourcesConsommation
from millegrilles_messages.messages.CleCertificat import CleCertificat


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

    async def run(self):
        self.__logger.info("ExtracteurGrosFichiers Run")

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


async def main():
    config = dict()

    extracteur = ExtracteurGrosFichiers(config)
    extracteur.preparer_dechiffrage()
    await extracteur.run()
