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
CONST_PATH_CHIFFRE = 'chiffre'
CONST_PATH_DECHIFFRE = 'dechiffre'
CONST_PATH_CUUIDS = 'cuuids'
CONST_PATH_ROOT = 'root'

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
        await recuperer_fichiers(self.__config.path_extraction, self.__config.url_consignation, self.__ssl_context, producer, queue_fuuids)

        # Indiquer que le download est termine
        self.__event_downloader.set()

        # Attendre que le dechiffrage soit termine
        await self.__event_dechiffrer.wait()

        # Traiter les cuuids
        await recuperer_cuuids(self.__config.path_extraction, self.__clecert, producer)

    async def traiter_reponse(self, message, module_messages: MessagesThread):
        self.__logger.info("Message dropped : %s" % json.dumps(message.parsed, indent=2))

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
            # self.__logger.debug("Reponse GrosFichiers parsed : %s" % reponse_grosfichiers_parsed)
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
                            await loop.run_in_executor(executor, dechiffrer_fichier, self.__config.path_extraction, self.__clecert, fuuid, fichier, reponse_parsed)
                            mapper_cuuids(self.__config.path_extraction, fichier)
                        except Exception:
                            self.__logger.exception("Erreur traitement fichier %s" % fuuid)

                else:
                    self.__logger.debug("Ignorer fuuid %s (pas un GrosFichiers fuuid_v_courante" % fuuid)


async def recuperer_fichiers(path_extraction: str, url_consignation: str, ssl_context, producer, queue_fuuids):
    __logger.info("recuperer_fichiers Debut")

    os.makedirs(path.join(path_extraction, CONST_PATH_CHIFFRE), exist_ok=True)
    os.makedirs(path.join(path_extraction, CONST_PATH_DECHIFFRE), exist_ok=True)

    conn = aiohttp.TCPConnector(ssl_context=ssl_context)
    async with aiohttp.ClientSession(connector=conn) as session:
        await download_liste_fichiers(session, path_extraction, url_consignation, producer, queue_fuuids)

    __logger.info("recuperer_fichiers Fin")


async def download_liste_fichiers(session, path_extraction, url_consignation: str, producer, queue_fuuids):

    path_get_fichiers = url_consignation + path.join('/fichiers_transfert', 'backup', 'liste')
    __logger.debug("get_liste_fichiers Path %s" % path_get_fichiers)

    # Recuperer la liste de tous les fichiers en consignation
    async with session.get(path_get_fichiers) as resp:
        __logger.debug("Reponse status %d" % resp.status)

        async for line in resp.content:
            fuuid = line.strip().decode('utf-8')
            path_fuuid_local = path.join(path_extraction, CONST_PATH_CHIFFRE, fuuid)
            path_fuuid_dechiffre = path.join(path_extraction, CONST_PATH_DECHIFFRE, fuuid)

            # Verifier si le fichier existe deja
            try:
                os.stat(path_fuuid_dechiffre)
                __logger.debug("Fichier local deja dechiffre : %s" % path_fuuid_dechiffre)
            except FileNotFoundError:
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


def dechiffrer_fichier(path_extraction: str, clecert, fuuid, info_fichier, cle_fichier):
    cle_info = dechiffrer_doc(cle_fichier, clecert, fuuid, info_fichier)

    # Dechiffrer fichier
    decipher = DecipherMgs4.from_info(clecert, cle_info)
    path_fuuid_chiffre = path.join(path_extraction, CONST_PATH_CHIFFRE, fuuid)
    path_fuuid_dechiffre = path.join(path_extraction, CONST_PATH_DECHIFFRE, fuuid)

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

    # Supprimer fichier chiffre
    os.unlink(path_fuuid_chiffre)


def dechiffrer_doc(cle_fichier, clecert, hachage_bytes, info_fichier):
    cle_info = cle_fichier['cles'][hachage_bytes]

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

    return cle_info


def mapper_cuuids(path_extraction: str, fichier_info):
    fuuid = fichier_info['fuuid_v_courante']
    nom_fichier = fichier_info['nom']
    path_fuuid_dechiffre = path.join(path_extraction, CONST_PATH_DECHIFFRE, fuuid)

    for cuuid in fichier_info['cuuids']:
        cuuid_path = path.join(path_extraction, CONST_PATH_CUUIDS, cuuid)
        path_fichier = path.join(cuuid_path, nom_fichier)
        os.makedirs(cuuid_path, exist_ok=True)
        os.link(path_fuuid_dechiffre, path_fichier)


async def recuperer_cuuids(path_extraction, clecert, producer):

    limit = 10
    skip = 0

    while True:
        requete = {"skip": skip, "limit": limit}
        reponse_cuuids = await producer.executer_requete(
            requete, "GrosFichiers", action='syncCuuids', exchange=Constantes.SECURITE_PRIVE)
        reponse_cuuids_parsed = reponse_cuuids.parsed
        liste_cuuids = reponse_cuuids_parsed['liste']
        if len(liste_cuuids) == 0:
            break  # Done

        skip = skip + len(liste_cuuids)

        for cuuid in liste_cuuids:
            try:
                await mapper_cuuid(path_extraction, clecert, producer, cuuid)
            except KeyError:
                __logger.exception("Erreur dechiffrage cuuid %s" % cuuid)

        __logger.debug("recuperer_cuuids Reponse %s" % reponse_cuuids_parsed)


async def mapper_cuuid(path_extraction: str, clecert, producer, cuuid_info):
    tuuid = cuuid_info['tuuid']
    metadata_chiffre = cuuid_info['metadata']
    ref_hachage_bytes = metadata_chiffre['ref_hachage_bytes']

    requete = {"domaine": "GrosFichiers", "liste_hachage_bytes": [ref_hachage_bytes]}
    reponse = await producer.executer_requete(
        requete, "MaitreDesCles", action='dechiffrage', exchange=Constantes.SECURITE_PRIVE)
    reponse_parsed = reponse.parsed
    if reponse_parsed.get('ok') is False:
        __logger.debug("Cle %s inconnue tuuid" % tuuid)
    else:
        __logger.debug("Reponse cle : %s" % reponse_parsed)

    # dechiffrer_doc(cle_fichier, clecert, ref_hachage_bytes, cuuid_info)
    cle_fichier = reponse_parsed['cles'][ref_hachage_bytes]
    cle_fichier['header'] = metadata_chiffre['header']
    metadata_bytes = multibase.decode(metadata_chiffre['data_chiffre'].encode('utf-8'))
    decipher_metadata = DecipherMgs4.from_info(clecert, cle_fichier)
    metadata_dechiffre_bytes = decipher_metadata.update(metadata_bytes)
    metadata_dechiffre_bytes = metadata_dechiffre_bytes + decipher_metadata.finalize()
    metadata_dict = json.loads(metadata_dechiffre_bytes.decode('utf-8'))
    cuuid_info.update(metadata_dict)

    nom_cuuid = cuuid_info['nom']
    cuuids = cuuid_info.get('cuuids') or list()
    __logger.debug("Cuuid info dechiffre %s (tuuid %s, cuuids : %s) : %s" % (nom_cuuid, tuuid, cuuids, cuuid_info))

    path_cuuid = path.join(path_extraction, CONST_PATH_CUUIDS, tuuid)
    os.makedirs(path_cuuid, exist_ok=True)

    if cuuid_info.get('favoris') is True:
        # Creer le cuuid sous user_id
        user_id = cuuid_info['user_id']
        path_userid = path.join(path_extraction, CONST_PATH_ROOT, user_id)
        os.makedirs(path_userid, exist_ok=True)

        path_favoris = path.join(path_userid, nom_cuuid)
        try:
            os.symlink(path_cuuid, path_favoris, target_is_directory=True)
        except FileExistsError:
            pass

    for cuuid_link in cuuids:
        path_cuuid_base = path.join(path_extraction, CONST_PATH_CUUIDS, cuuid_link)
        os.makedirs(path_cuuid_base, exist_ok=True)
        path_cuuid_link = path.join(path_cuuid_base, nom_cuuid)
        try:
            os.symlink(path_cuuid, path_cuuid_link, target_is_directory=True)
        except FileExistsError:
            pass


async def main(ca: Optional[str], path_extraction: Optional[str], url_consignation: Optional[str]):
    config = dict()

    if ca is not None:
        config['CA_PEM'] = ca

    if path_extraction is not None:
        config[Constantes.ENV_PATH_EXTRACTION] = path_extraction

    if url_consignation is not None:
        config[Constantes.ENV_URL_CONSIGNATION] = url_consignation

    extracteur = ExtracteurGrosFichiers(config)
    await extracteur.preparer()
    await extracteur.run()
