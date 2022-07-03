import asyncio
import getpass
import logging
import json
import lzma

import multibase
import tarfile

from os import path, makedirs, unlink
from typing import Optional

from millegrilles_messages.backup.Configuration import ConfigurationBackup
from millegrilles_messages.messages import Constantes
from millegrilles_messages.messages.ValidateurMessage import ValidateurMessage, ValidateurCertificatCache
from millegrilles_messages.messages.EnveloppeCertificat import EnveloppeCertificat
from millegrilles_messages.messages.CleCertificat import CleCertificat
from millegrilles_messages.messages.FormatteurMessages import SignateurTransactionSimple, FormatteurMessageMilleGrilles
from millegrilles_messages.chiffrage.Mgs3 import DecipherMgs3

from millegrilles_messages.messages.MessagesThread import MessagesThread
from millegrilles_messages.messages.MessagesModule import RessourcesConsommation


class DemarreurBackup:

    def __init__(self, config: dict, backup: bool, complet: bool, regenerer: str):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__config = ConfigurationBackup()
        self.__backup = backup
        self.__complet = complet
        self.__regenerer = regenerer

        self.__messages_thread: Optional[MessagesThread] = None
        self.__demarrage_confirme: Optional[asyncio.Event()] = None
        self.__stop_event: Optional[asyncio.Event()] = None

        # Parse configuration environnement
        self.__config.parse_config(config)

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

    async def traiter_reponse(self, message, module_messages: MessagesThread):
        self.__logger.info("Message recu : %s" % json.dumps(message.parsed, indent=2))

        message_parsed = message.parsed
        if message_parsed.get('ok') == True:
            self.__logger.info("Backup demarre")
        else:
            self.__logger.warning("Erreur demarrage du backup : %s" % message_parsed.get('err'))

        self.__demarrage_confirme.set()

    async def run(self):
        # Demarrer traitement messages
        await self.__messages_thread.start_async()

        tasks = [
            asyncio.create_task(self.__messages_thread.run_async()),
            asyncio.create_task(self.run_demarrer_backup()),
        ]

        # Execution de la loop avec toutes les tasks
        await asyncio.tasks.wait(tasks, return_when=asyncio.tasks.FIRST_COMPLETED)

    async def run_demarrer_backup(self):
        self.__logger.info("Attente connexion MQ")
        await self.__messages_thread.attendre_pret(10)

        if self.__backup:
            action = 'demarrerBackupTransactions'
            commande = {'complet': self.__complet}
            producer = self.__messages_thread.get_producer()
            self.__logger.info("Transmettre commande backup")
            reponse = await producer.executer_commande(commande, 'fichiers', action=action,
                                                       exchange=Constantes.SECURITE_PRIVE)

            if reponse.parsed.get('ok'):
                self.__logger.info("BACKUP DEMARRE (OK) ")
            else:
                self.__logger.error("ERREUR : Reponse : %s" % reponse.parsed.get('err'))

        if self.__regenerer:
            action = 'regenerer'
            domaine = self.__regenerer
            commande = {}
            producer = self.__messages_thread.get_producer()
            self.__logger.info("Transmettre commande backup")
            reponse = await producer.executer_commande(commande, domaine, action=action,
                                                       exchange=Constantes.SECURITE_PROTEGE)

            if reponse.parsed.get('ok'):
                self.__logger.info("REGENERATION DEMARREE (OK) ")
            else:
                self.__logger.error("ERREUR : Reponse : %s" % reponse.parsed.get('err'))


async def main(backup: bool, complet: bool, regenerer: str):
    config = dict()

    demarreur = DemarreurBackup(config, backup, complet, regenerer)
    await demarreur.preparer()
    await demarreur.run()
