# Extracteur de GrosFichiers
import os

import aiohttp
import asyncio
import logging
import json
import ssl
import concurrent.futures
import multibase

from os import path
from typing import Optional

from millegrilles_messages.backup.Configuration import ConfigurationExtracteurGrosFichiers
from millegrilles_messages.messages import Constantes

from millegrilles_messages.messages.MessagesThread import MessagesThread
from millegrilles_messages.messages.MessagesModule import RessourcesConsommation
from millegrilles_messages.messages.CleCertificat import CleCertificat
from millegrilles_messages.chiffrage.Mgs4 import DecipherMgs4

__logger = logging.getLogger(__name__)

CONST_CHUNK_SIZE = 64 * 1024
CONST_PATH_CHIFFRE = '/tmp/grosfichiers/chiffre'
CONST_PATH_DECHIFFRE = '/tmp/grosfichiers/dechiffre'
CONST_PATH_CUUIDS = '/tmp/grosfichiers/cuuids'

executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)


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

        self.__event_dechiffrer = asyncio.Event()
        self.__event_downloader = asyncio.Event()

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

        self.preparer_dechiffrage()

    def preparer_dechiffrage(self):
        self.__clecert = CleCertificat.from_files(self.__config.key_pem_path, self.__config.cert_pem_path)
        if not self.__clecert.cle_correspondent():
            raise Exception("Fichiers Cle/Cert ne correspondent pas")

        self.__ssl_context = ssl.create_default_context(cafile=self.__config.ca_pem_path)
        self.__ssl_context.load_cert_chain(self.__config.cert_pem_path, self.__config.key_pem_path)

    async def run(self):
        self.__logger.info("ExtracteurGrosFichiers Run")

        # Demarrer traitement messages
        await self.__messages_thread.start_async()

        queue_fuuids = asyncio.Queue(maxsize=1000)

        tasks = [
            asyncio.create_task(self.__messages_thread.run_async()),
            asyncio.create_task(self.traiter_fichiers(queue_fuuids)),
            asyncio.create_task(self.dechiffrer_fichiers(queue_fuuids)),
        ]

        # Execution de la loop avec toutes les tasks
        await asyncio.tasks.wait(tasks, return_when=asyncio.tasks.FIRST_COMPLETED)

        self.__logger.info("ExtracteurGrosFichiers Done")

    async def traiter_fichiers(self, queue_fuuids):
        await self.__messages_thread.attendre_pret()
        producer = self.__messages_thread.get_producer()
        await recuperer_fichiers(self.__config.url_consignation, self.__ssl_context, producer, queue_fuuids)

        # Indiquer que le download est termine
        self.__event_downloader.set()

        # Attendre que le dechiffrage soit termine
        await self.__event_dechiffrer.wait()

    async def traiter_reponse(self, message, module_messages: MessagesThread):
        self.__logger.info("Message recu : %s" % json.dumps(message.parsed, indent=2))

        message_parsed = message.parsed
        # if message_parsed.get('ok') == True:
        #     self.__logger.info("Backup demarre")
        # else:
        #     self.__logger.warning("Erreur demarrage du backup : %s" % message_parsed.get('err'))
        #
        # self.__demarrage_confirme.set()

    async def dechiffrer_fichiers(self, queue_fuuids):

        await self.__messages_thread.attendre_pret()
        producer = self.__messages_thread.get_producer()

        while True:
            if queue_fuuids.empty():
                # Indiquer que le dechiffrage est termine
                self.__event_dechiffrer.set()
            fuuid = await queue_fuuids.get()
            self.__event_dechiffrer.clear()

            # Verifier le type de GrosFichiers (ignorer attachments, messagerie, etc.)
            requete_grosfichiers = {"fuuids_documents": [fuuid]}
            reponse_grosfichiers = await producer.executer_requete(
                requete_grosfichiers, "GrosFichiers", action='documentsParFuuid', exchange=Constantes.SECURITE_PRIVE)
            reponse_grosfichiers_parsed = reponse_grosfichiers.parsed
            self.__logger.debug("Reponse GrosFichiers parsed : %s" % reponse_grosfichiers_parsed)
            try:
                fichier = reponse_grosfichiers_parsed['fichiers'][0]
                fuuid_v_courante = fichier['fuuid_v_courante']
            except (IndexError, KeyError):
                self.__logger.debug("Ignorer fuuid %s (fichier inconnu de GrosFichiers)" % fuuid)
            else:
                if fuuid_v_courante == fuuid:
                    # Recuperer la cle pour dechiffrer le fichier
                    requete = {"domaine": "GrosFichiers", "liste_hachage_bytes": [fuuid]}
                    reponse = await producer.executer_requete(
                        requete, "MaitreDesCles", action='dechiffrage', exchange=Constantes.SECURITE_PRIVE)
                    reponse_parsed = reponse.parsed
                    if reponse_parsed.get('ok') is False:
                        self.__logger.debug("Cle %s inconnue" % fuuid)
                    else:
                        self.__logger.debug("Reponse cle : %s" % reponse_parsed)
                        loop = asyncio.get_running_loop()
                        try:
                            await loop.run_in_executor(executor, dechiffrer_fichier, self.__clecert, fuuid, fichier, reponse_parsed)
                            mapper_cuuids(fichier)
                        except Exception:
                            self.__logger.exception("Erreur traitement fichier %s" % fuuid)

                else:
                    self.__logger.debug("Ignorer fuuid %s (pas un GrosFichiers fuuid_v_courante" % fuuid)


async def recuperer_fichiers(url_consignation: str, ssl_context, producer, queue_fuuids):
    __logger.info("recuperer_fichiers Debut")

    os.makedirs(CONST_PATH_CHIFFRE, exist_ok=True)
    os.makedirs(CONST_PATH_DECHIFFRE, exist_ok=True)

    conn = aiohttp.TCPConnector(ssl_context=ssl_context)
    async with aiohttp.ClientSession(connector=conn) as session:
        await download_liste_fichiers(session, url_consignation, producer, queue_fuuids)

    __logger.info("recuperer_fichiers Fin")


async def download_liste_fichiers(session, url_consignation: str, producer, queue_fuuids):

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

            await queue_fuuids.put(fuuid)


def dechiffrer_fichier(clecert, fuuid, info_fichier, cle_fichier):
    cle_info = cle_fichier['cles'][fuuid]

    # Dechiffrer metadata
    cle_metadata = cle_info.copy()
    metadata_chiffre = info_fichier['version_courante']['metadata']
    cle_metadata['header'] = metadata_chiffre['header']
    metadata_bytes = multibase.decode(metadata_chiffre['data_chiffre'].encode('utf-8'))
    decipher_metadata = DecipherMgs4.from_info(clecert, cle_metadata)
    metadata_dechiffre_bytes = decipher_metadata.update(metadata_bytes)
    metadata_dechiffre_bytes = metadata_dechiffre_bytes + decipher_metadata.finalize()
    metadata_dict = json.loads(metadata_dechiffre_bytes.decode('utf-8'))
    info_fichier.update(metadata_dict)

    # Dechiffrer fichier
    decipher = DecipherMgs4.from_info(clecert, cle_info)
    path_fuuid_chiffre = path.join(CONST_PATH_CHIFFRE, fuuid)
    path_fuuid_dechiffre = path.join(CONST_PATH_DECHIFFRE, fuuid)

    with open(path_fuuid_chiffre, 'rb') as fichier_chiffre:
        try:
            with open(path_fuuid_dechiffre, 'xb') as fichier_dechiffre:
                data = fichier_chiffre.read(CONST_CHUNK_SIZE)

                while len(data) > 0:
                    data = decipher.update(data)
                    fichier_dechiffre.write(data)
                    data = fichier_chiffre.read(CONST_CHUNK_SIZE)

                data = decipher.finalize()
                fichier_dechiffre.write(data)
        except FileExistsError:
            __logger.debug("Fichier dechiffre existe : %s" % fuuid)


def mapper_cuuids(fichier_info):
    fuuid = fichier_info['fuuid_v_courante']
    nom_fichier = fichier_info['nom']
    path_fuuid_dechiffre = path.join(CONST_PATH_DECHIFFRE, fuuid)

    for cuuid in fichier_info['cuuids']:
        cuuid_path = path.join(CONST_PATH_CUUIDS, cuuid)
        path_fichier = path.join(cuuid_path, nom_fichier)
        os.makedirs(cuuid_path, exist_ok=True)
        os.link(path_fuuid_dechiffre, path_fichier)


async def main(ca: Optional[str]):
    config = dict()

    if ca is not None:
        config['CA_PEM'] = ca

    extracteur = ExtracteurGrosFichiers(config)
    await extracteur.preparer()
    await extracteur.run()
