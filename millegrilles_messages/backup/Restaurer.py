import asyncio
import datetime
import getpass
import gzip
import logging
import json
import lzma
import os
import time
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor

import multibase
import tarfile

from os import path, makedirs, unlink
from typing import Optional

import pytz

from millegrilles_messages.backup.Configuration import ConfigurationBackup
from millegrilles_messages.messages import Constantes as ConstantesMillegrilles
from millegrilles_messages.messages.ValidateurMessage import ValidateurMessage, ValidateurCertificatCache
from millegrilles_messages.messages.EnveloppeCertificat import EnveloppeCertificat
from millegrilles_messages.messages.CleCertificat import CleCertificat
from millegrilles_messages.messages.FormatteurMessages import SignateurTransactionSimple, FormatteurMessageMilleGrilles
from millegrilles_messages.messages.MessagesModule import MessageWrapper
from millegrilles_messages.chiffrage.Mgs4 import DecipherMgs4

from millegrilles_messages.messages.MessagesThread import MessagesThread
from millegrilles_messages.messages.MessagesModule import RessourcesConsommation


PATH_RESTAURATION = '_RESTAURATION'
TAILLE_BUFFER = 128 * 1024
RESTAURATION_BATCH_SIZE = 100


class RestaurateurArchives:

    def __init__(self, config: dict, transactions: bool, work_path: str, clecert_ca: CleCertificat, domaine: Optional[str], delai: Optional[int]):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__config = ConfigurationBackup()
        # self.__archive = archive
        self.__transactions = transactions
        self.__work_path = work_path
        self.__clecert_ca = clecert_ca
        self.__domaine = domaine
        self.__delai = delai

        self.__enveloppe_ca: Optional[EnveloppeCertificat] = None
        self.__formatteur: Optional[FormatteurMessageMilleGrilles] = None
        self.__validateur_certificats: Optional[ValidateurCertificatCache] = None
        self.__validateur_messages: Optional[ValidateurMessage] = None

        # Parse configuration environnement
        self.__config.parse_config(config)

        self.__restaurateur_transactions: Optional[RestaurateurTransactions] = None

    def preparer_dechiffrage(self):
        path_ca = self.__config.ca_pem_path
        try:
            self.__enveloppe_ca = EnveloppeCertificat.from_file(path_ca)
        except FileNotFoundError:
            self.__logger.warning("Chiffrage annule, CA introuvable (path %s)", path_ca)
            return

        clecert = CleCertificat.from_files(self.__config.key_pem_path, self.__config.cert_pem_path)

        signateur = SignateurTransactionSimple(clecert)
        self.__formatteur = FormatteurMessageMilleGrilles(self.__enveloppe_ca.idmg, signateur)
        self.__validateur_certificats = ValidateurCertificatCache(self.__enveloppe_ca)
        self.__validateur_messages = ValidateurMessage(self.__validateur_certificats)

    async def preparer_mq(self, rechiffrer: bool):
        self.__restaurateur_transactions = RestaurateurTransactions(self.__config, self.__clecert_ca, self.__work_path,
                                                                    rechiffrer=rechiffrer, domaine=self.__domaine,
                                                                    delai=self.__delai)
        await self.__restaurateur_transactions.preparer()

    async def run(self):
        # if self.__archive is not None:
        #     self.__logger.info("Traiter archive %s" % self.__archive)
        #     path_archive = await self.extraire_archive()
        #     path_archive_dechiffree = await self.dechiffrer(path_archive)
        #     await self.extraire_archive_dechiffree(path_archive_dechiffree)

        if self.__restaurateur_transactions is not None:
            self.__logger.info("Traiter transactions")
            await self.__restaurateur_transactions.run()

    # async def extraire_archive(self) -> str:
    #     makedirs(self.__work_path, mode=0o755, exist_ok=True)
    #
    #     path_archive = None
    #
    #     with tarfile.open(self.__archive, 'r') as fichier_tar:
    #         tar_member = fichier_tar.next()
    #         while tar_member is not None:
    #             if tar_member.name != 'catalogue.json':
    #                 path_archive = path.join(self.__work_path, tar_member.name)
    #
    #             fichier_tar.extract(tar_member, self.__work_path)
    #             tar_member = fichier_tar.next()
    #
    #     return path_archive

    # async def dechiffrer(self, path_archive: str) -> str:
    #     catalogue_path = path.join(self.__work_path, 'catalogue.json')
    #     with open(catalogue_path, 'r') as fichier:
    #         catalogue = asyncio.to_thread(json.load, fichier)
    #
    #     verifier_enveloppe = True
    #     try:
    #         if os.environ.get('VALIDATION_SKIP') is not None:
    #             verifier_enveloppe = False
    #     except KeyError:
    #         pass
    #
    #     if verifier_enveloppe is True:
    #         enveloppe = await self.__validateur_messages.verifier(catalogue, utiliser_date_message=True)
    #
    #     cle_dechiffree = self.__clecert_ca.dechiffrage_asymmetrique(catalogue['cle'])
    #     decipher = DecipherMgs4(cle_dechiffree, catalogue['header'])
    #
    #     path_archive_dechiffree = '.'.join(path_archive.split('.')[:-1])
    #     with open(path_archive_dechiffree, 'wb') as fichier_output:
    #         with open(path_archive, 'rb') as fichier:
    #             def read_contenu():
    #                 buffer_bytes = fichier.read(TAILLE_BUFFER)
    #                 while len(buffer_bytes) > 0:
    #                     data = decipher.update(buffer_bytes)
    #                     fichier_output.write(data)
    #                     buffer_bytes = fichier.read(TAILLE_BUFFER)
    #
    #                 data = decipher.finalize()
    #                 fichier_output.write(data)
    #             await asyncio.to_thread(read_contenu)
    #
    #     self.__logger.debug("Dechiffrage %s OK" % path_archive)
    #     unlink(path_archive)
    #
    #     return path_archive_dechiffree

    # async def extraire_archive_dechiffree(self, path_archive):
    #     with tarfile.open(path_archive, 'r') as tar_file:
    #         tar_file.extractall(self.__work_path)
    #     unlink(path_archive)


class CataloguesProcessEntry:

    def __init__(self, catalogue, nom_domaine, catalogue_id, contenu):
        self.catalogue = catalogue
        self.nom_domaine = nom_domaine
        self.catalogue_id = catalogue_id
        self.contenu = contenu


class TransactionProcessEntry:

    def __init__(self, transaction: dict, domaine: str, compteur: int):
        # self.data_transactions = data_transactions
        self.transaction = transaction
        self.domaine = domaine
        self.compteur = compteur


class TransactionsTermineEntry:

    def __init__(self):
        pass


class RestaurateurTransactions:

    def __init__(self, config: ConfigurationBackup, clecert_ca: CleCertificat, work_path: str, rechiffrer: bool, domaine: Optional[str], delai: Optional[int]):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__config = config
        self.__clecert_ca = clecert_ca
        self.__work_path = work_path
        self.__rechiffrer = rechiffrer
        self.__stop_event: Optional[asyncio.Event] = None
        self.__restauration_complete_event: Optional[asyncio.Event] = None
        self.__messages_thread: Optional[MessagesThread] = None
        self.__certificats_rechiffrage: Optional[list[EnveloppeCertificat]] = None
        self.__domaine = domaine
        self.__delai = delai
        self.__compte_transactions_traitees = 0

        self.__path_fichier_archives = path.join(work_path, 'liste.txt')
        self.__fp_fichiers_archive = None
        self.__date_recu_catalogue: Optional[datetime.datetime] = None
        self.__timeout_traitement_catalogue_desactive = False
        self.__catalogues_recus_event: Optional[asyncio.Event] = None
        # self.__domaine_complete_queue: Optional[asyncio.Queue] = None
        self.__catalogues_queue: Optional[asyncio.Queue] = None
        self.__regeneration_event: Optional[asyncio.Event] = None
        self.__fichiers_process_queue: Optional[asyncio.Queue] = None
        self.__transactions_process_queue: Optional[asyncio.Queue] = None
        self.__traitement_transactions_termine = None
        self.__process_pool = None
        self.__thread_pool = None

    @property
    def validateur_messages(self):
        return self.__messages_thread.get_validateur_messages()

    async def preparer(self):
        makedirs(self.__work_path, mode=0o755, exist_ok=True)

        reply_res = RessourcesConsommation(self.traiter_reponse)
        reply_res.ajouter_rk(ConstantesMillegrilles.SECURITE_PROTEGE, 'evenement.*.regenerationMaj')
        self.__stop_event = asyncio.Event()
        self.__restauration_complete_event = asyncio.Event()
        self.__catalogues_recus_event = asyncio.Event()
        # self.__domaine_complete_queue = asyncio.Queue()
        messages_thread = MessagesThread(self.__stop_event)
        messages_thread.set_reply_ressources(reply_res)
        self.__catalogues_queue = asyncio.Queue()
        self.__regeneration_event = asyncio.Event()

        self.__fichiers_process_queue = asyncio.Queue(maxsize=1)
        self.__transactions_process_queue = asyncio.Queue(maxsize=200)
        self.__traitement_transactions_termine = asyncio.Event()

        # Note : le traitement de dechiffrage est CPU intensive mais ne peut pas etre "pickled", on aurait
        #        besoin d'un ProcessPoolExecutor ici pour permettre traitement en parallele
        self.__process_pool = ProcessPoolExecutor(max_workers=1)
        self.__thread_pool = ThreadPoolExecutor(max_workers=1)

        config = {
            'CERT_PEM': self.__config.cert_pem_path,
            'KEY_PEM': self.__config.key_pem_path,
            'CA_PEM': self.__config.ca_pem_path,
        }
        messages_thread.set_env_configuration(config)

        self.__messages_thread = messages_thread

    async def traiter_reponse(self, message: MessageWrapper, module_messages: MessagesThread):
        # self.__logger.debug("traiter_reponse Message recu : %s" % json.dumps(message.parsed, indent=2))

        try:
            action = message.routage.get('action')
        except AttributeError:
            action = None
        correlation_id = message.correlation_id

        if correlation_id == 'restaurationCompletee':
            self.__logger.info("traiter_reponse Tous les catalogues ont ete recus")
            self.__catalogues_recus_event.set()
        elif correlation_id == 'domaineComplete':
            self.touch_activite_transactions("traiter_reponse message domaineComplete")
            # await self.__domaine_complete_queue.put(message)
            await self.__catalogues_queue.put(TransactionsTermineEntry())
            # await self.__transactions_process_queue.put(TransactionsTermineEntry())
        elif correlation_id == 'catalogueTransactions':
            self.touch_activite_transactions("traiter_reponse message catalogueTransactions")
            # await self.traiter_catalogue(message)
            await self.__catalogues_queue.put(message)
        elif action == 'regenerationMaj':
            if message.parsed.get('termine') is True:
                self.__regeneration_event.set()

        # if self.__restauration_complete_event.is_set() is False:
        #     # Mode recevoir liste fichiers/cles
        #     # try:
        #     #     cles = message_parsed['cles']
        #     #     self.__logger.info("Cles recues : %s", cles)
        #     #
        #     #     await asyncio.to_thread(self.conserver_liste_fichiers, cles)
        #     #
        #     # except KeyError:
        #     #     pass
        #
        #     try:
        #         if message_parsed['complet'] is True:
        #             self.__restauration_complete_event.set()
        #     except KeyError:
        #         pass

    async def run(self):
        # Demarrer traitement messages
        await self.__messages_thread.start_async()

        tasks = [
            asyncio.create_task(self.__messages_thread.run_async()),
            asyncio.create_task(self.run_traitement_transactions()),
            asyncio.create_task(self.traiter_catalogues_thread()),
            asyncio.create_task(self.send_transactions_thread()),
            # asyncio.create_task(self.complete_domaine_thread())
        ]

        # Creer les tasks de dechiffrage
        for i in range(0, 1):  # 1 seul thread, probleme sync regeneration
            task_dechiffrage = asyncio.create_task(self.parse_transactions_thread())
            tasks.append(task_dechiffrage)

        # Execution de la loop avec toutes les tasks
        await asyncio.tasks.wait(tasks, return_when=asyncio.tasks.FIRST_COMPLETED)

    async def run_traitement_transactions(self):
        self.__logger.info("Attendre MQ")
        await self.__messages_thread.attendre_pret()
        self.__logger.info("MQ pret")

        # if self.__rechiffrer is True:
        #     self.__logger.info("Recuperer certificats maitre des cles")
        #     producer = self.__messages_thread.get_producer()
        #     cert = await producer.executer_requete(
        #         dict(),
        #         domaine='MaitreDesCles', action='certMaitreDesCles', exchange=Constantes.SECURITE_PRIVE, timeout=10)
        #     cert_pem = ''.join(cert.parsed['certificat'])
        #     certificat_rechiffrage = EnveloppeCertificat.from_pem(cert_pem)
        #     if 'maitredescles' not in certificat_rechiffrage.get_roles:
        #         raise ValueError('Mauvais certificat de rechiffrage recu - doit avoir role maitredescles')
        #     self.__certificats_rechiffrage = [certificat_rechiffrage]

        await self.restaurer()

    def touch_activite_transactions(self, label: Optional[str] = None, desactiver_timeout=False):
        now = datetime.datetime.utcnow()
        self.__logger.debug("touch_activite_transactions Touch activite transactions %s : %s (desactive: %s)" % (label, now, desactiver_timeout))
        self.__date_recu_catalogue = now
        self.__timeout_traitement_catalogue_desactive = desactiver_timeout

    async def restaurer(self):
        producer = self.__messages_thread.get_producer()
        await producer.producer_pret().wait()

        # self.__fp_fichiers_archive = open(self.__path_fichier_archives, 'w')

        commande_demarrer = dict()
        if self.__domaine:
            commande_demarrer['domaines'] = [self.__domaine]

        reponse_demarrage = await producer.executer_commande(
            commande_demarrer, domaine='backup', action='restaurerTransactions',
            exchange=ConstantesMillegrilles.SECURITE_PRIVE)

        # self.__logger.info("restaurer Reponse demarrage restauration : %s", reponse_demarrage.parsed)
        if reponse_demarrage.parsed['ok'] is not True:
            raise Exception('restaurer Erreur demarrage restauration (service backup) : %s' % reponse_demarrage.parsed.get('err'))

        domaines = reponse_demarrage.parsed['domaines']

        self.__logger.info("restaurerAttente des transactions a restaurer")
        pending = {asyncio.create_task(self.__catalogues_recus_event.wait())}
        self.touch_activite_transactions("restaurer debut")
        expiration_attente = datetime.timedelta(seconds=60)

        while len(pending) > 0:
            done, pending = await asyncio.wait(pending, timeout=5)
            self.__logger.info("restaurer Emettre rapport restauration, transactions traitees : %d" % self.__compte_transactions_traitees)
            now = datetime.datetime.utcnow()
            if self.__timeout_traitement_catalogue_desactive is False and \
                    now - expiration_attente > self.__date_recu_catalogue:
                raise Exception('restaurer Erreur restauration - timeout attente transactions : %s (derniere action %s)' % (now, self.__date_recu_catalogue))

        self.__logger.info("restaurer Attendre fin de traitement des transactions")
        await self.__traitement_transactions_termine.wait()
        self.__logger.info("restaurer Tous les catalogues on ete recus et uploades, nombre transactions : %d" % self.__compte_transactions_traitees)
        await self.regenerer(producer, domaines)

    async def regenerer(self, producer, domaines: list):
        for domaine in domaines:
            nom_domaine = domaine['domaine']
            self.__logger.info("Regenerer domaine %s" % nom_domaine)
            commande = {'domaine': nom_domaine}
            self.__regeneration_event.clear()
            await producer.executer_commande(commande,
                                             domaine=nom_domaine, action='regenerer',
                                             exchange=ConstantesMillegrilles.SECURITE_PROTEGE, nowait=True)
            try:
                await asyncio.wait_for(self.__regeneration_event.wait(), 45)
                self.__logger.info("Regeneration %s terminee avec succes" % nom_domaine)
            except asyncio.TimeoutError:
                self.__logger.warning("Timeout regeneration %s, on continue" % nom_domaine)

    async def traiter_catalogues_thread(self):
        stop_task = asyncio.create_task(self.__stop_event.wait())
        pending = {stop_task}
        while self.__stop_event.is_set() is False:
            pending.add(asyncio.create_task(self.__catalogues_queue.get()))
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            if self.__stop_event.is_set():
                for p in pending:
                    p.cancel()
                    try:
                        await p
                    except asyncio.CancelledError:
                        pass  # OK
                break  # Stopped
            catalogue = done.pop().result()

            if isinstance(catalogue, TransactionsTermineEntry):
                await self.__fichiers_process_queue.put(catalogue)
                continue

            self.touch_activite_transactions("traiter_catalogues_thread Recu nouveau catalogue")
            self.__logger.info("traiter_catalogues_thread Recu nouveau catalogue")

            contenu = catalogue.parsed
            catalogue = contenu['catalogue']

            validateur_messages = self.validateur_messages
            enveloppe = await validateur_messages.verifier(catalogue, utiliser_date_message=True)

            # Parser le catalogue
            contenu_catalogue = json.loads(catalogue['contenu'])
            catalogue_id = catalogue['id']
            nom_domaine = contenu_catalogue['domaine']

            if enveloppe is not None:
                # Verifier que le domaine du certificat correspond au domaine du catalogue
                if nom_domaine in enveloppe.get_domaines:
                    entry = CataloguesProcessEntry(catalogue, nom_domaine, catalogue_id, contenu_catalogue)
                    await self.__fichiers_process_queue.put(entry)
                else:
                    self.__logger.error("Signature avec certificat du mauvais domaine - skip transactions %s" % catalogue_id)
            else:
                self.__logger.error("Aucun certificat trouve - skip transactions %s" % catalogue_id)

            self.touch_activite_transactions("traiter_catalogues_thread fin %s / %s" % (nom_domaine, catalogue_id))
            self.__logger.info("traiter_catalogues_thread Catalogue emis %s / %s" % (nom_domaine, catalogue_id))

            # Confirmer le traitement du catalogue
            producer = self.__messages_thread.get_producer()
            await producer.producer_pret().wait()

            # Demander prochain catalogue du backupService
            commande = {'catalogue_id': catalogue_id}
            await producer.executer_commande(
                commande, ConstantesMillegrilles.DOMAINE_BACKUP, 'catalogueTraite',
                exchange=ConstantesMillegrilles.SECURITE_PRIVE, nowait=True
            )

    async def parse_transactions_thread(self):
        while not self.__stop_event.is_set():
            entry: CataloguesProcessEntry = await self.__fichiers_process_queue.get()

            if isinstance(entry, TransactionsTermineEntry):
                await self.__transactions_process_queue.put(entry)
                continue

            try:
                self.touch_activite_transactions("traiter_catalogues_thread debut %s / %s" % (entry.nom_domaine, entry.catalogue_id))
                # Verifier
                try:
                    # debut_dechiffrage = datetime.datetime.utcnow()
                    # self.__logger.info("parse_transactions_thread Dechiffrer catalogue %s/%s" % (entry.nom_domaine, entry.catalogue_id))
                    await self.traiter_transactions_fichier(entry.contenu)
                    # duree_dechiffrage = datetime.datetime.utcnow() - debut_dechiffrage
                    # self.__logger.info("parse_transactions_thread Dechiffrage complet (duree: %s) catalogue %s/%s" % (
                    #    duree_dechiffrage, entry.nom_domaine, entry.catalogue_id))
                except ValueError:
                    self.__logger.exception("Erreur dechiffrage catalogue %s/%s" % (entry.nom_domaine, entry.catalogue_id))
            except:
                self.__logger.exception("traiter_transactions_thread Erreur traitement catalogue %s/%s" % (entry.nom_domaine, entry.catalogue_id))
            # finally:
            #     # Confirmer le traitement du catalogue
            #     producer = self.__messages_thread.get_producer()
            #     await producer.producer_pret().wait()
            #     commande = {'catalogue_id': entry.catalogue_id}
            #     await producer.executer_commande(
            #         commande, ConstantesMillegrilles.DOMAINE_BACKUP, 'catalogueTraite',
            #         exchange=ConstantesMillegrilles.SECURITE_PRIVE, nowait=True
            #     )

    async def traiter_transactions(self):
        producer = self.__messages_thread.get_producer()

        domaines = dict()
        with open(self.__path_fichier_archives, 'r') as fichier:
            for ligne_fichier in fichier:
                self.__logger.debug("Traiter %s" % ligne_fichier)
                nom_fichier = ligne_fichier.strip()

                if self.__domaine is not None:
                    domaine_fichier = nom_fichier.split('/')[0]
                    if self.__domaine != domaine_fichier:
                        continue  # Skip, mauvais domaine

                # Bounce la requete de fichier de backup
                requete = {'fichierBackup': nom_fichier}
                resultat = await producer.executer_requete(requete, domaine='backup',
                                                           action='getBackupTransaction', exchange='2.prive')
                transaction_backup = resultat.parsed['backup']
                contenu_transaction = json.loads(transaction_backup['contenu'])
                try:
                    domaine = contenu_transaction['domaine']
                except KeyError:
                    self.__logger.error("Transaction %s n'a pas de champ domaine - ** SKIP **" % nom_fichier)
                    continue

                try:
                    meta_domaine = domaines[domaine]
                except KeyError:
                    meta_domaine = {'transactions': 0, 'fichiers': list()}
                    domaines[domaine] = meta_domaine

                self.__logger.debug("Fichier transaction %s" % nom_fichier)
                meta_domaine['fichiers'].append(nom_fichier)

                try:
                    meta_traitement = await self.traiter_transactions_fichier(contenu_transaction)
                    meta_domaine['transactions'] = meta_domaine['transactions'] + meta_traitement['nb_transactions_traitees']
                except ValueError:
                    self.__logger.exception("Erreur dechiffrage fichier %s" % nom_fichier)

                if self.__delai is not None:
                    try:
                        await asyncio.sleep(self.__delai)
                    except asyncio.TimeoutError:
                        pass
                    self.touch_activite_transactions("traiter_catalogues_thread apres delai")

        self.__logger.info(" ** INFO RESTAURATION DOMAINES ** ")
        for nom_domaine, meta_domaine in domaines.items():
            # Rapport restauration pour domaine
            # self.__logger.info("Domaine %s : %s transactions" % (nom_domaine, meta_domaine['transactions']))

            self.__logger.info("Regenerer domaine %s" % domaine)
            commande = {'domaine': nom_domaine}
            self.touch_activite_transactions("traiter_catalogues_thread regeneration %s" % nom_domaine)
            await producer.executer_commande(commande,
                                             domaine=nom_domaine, action='regenerer',
                                             exchange=ConstantesMillegrilles.SECURITE_PROTEGE, nowait=True)

    async def traiter_transactions_fichier(self, backup: dict) -> dict:
        domaine = backup['domaine']
        nombre_transactions_catalogue = backup['nombre_transactions']
        info_meta = {'domaine': domaine, 'nb_transactions_catalogue': nombre_transactions_catalogue}

        certificats = self.preparer_certificats(backup['certificats'])

        producer = self.__messages_thread.get_producer()
        await producer.producer_pret().wait()

        self.touch_activite_transactions("traiter_transactions_fichier Emettre certificat")

        # Emettre les certificats vers CorePki
        for commande_certificat in certificats.values():
            await producer.executer_commande(commande_certificat,
                                             domaine='CorePki', action='certificat',
                                             exchange=ConstantesMillegrilles.SECURITE_PROTEGE,  # timeout=1,
                                             nowait=True)

        # Dechiffrer transactions
        debut_dechiffrage = datetime.datetime.utcnow()
        try:
            self.touch_activite_transactions("traiter_transactions_fichier Dechiffrer transactions", desactiver_timeout=True)
            self.__logger.info("Debut dechiffrage")
            try:
                dechiffrage = backup['dechiffrage']
            except KeyError:
                # Ancien format
                if backup['format'] != 'mgs4':
                    raise Exception("Format de chiffrage non supporte")
                cle = backup['cle']
                nonce = backup['header']
            else:
                # Nouveau format
                if dechiffrage['format'] != 'mgs4':
                    raise Exception("Format de chiffrage non supporte")
                nonce = dechiffrage['nonce']
                for cle in dechiffrage['cles'].values():
                    break
                else:
                    raise Exception("Aucunes cles")

            cle_dechiffree = self.__clecert_ca.dechiffrage_asymmetrique(cle)
            decipher = DecipherMgs4(cle_dechiffree, nonce)
            data = backup['data_transactions']
            nombre_transactions_traitees = await self.extraire_transactions(data, decipher, domaine)
            # loop = asyncio.get_running_loop()
            # data_transactions = await loop.run_in_executor(self.__thread_pool, self.extraire_transactions, data, decipher)
            # data_transactions = await asyncio.to_thread(self.extraire_transactions, data, decipher)
        finally:
            self.touch_activite_transactions("traiter_transactions_fichier Transactions dechiffrees", desactiver_timeout=False)

        if self.__logger.isEnabledFor(logging.INFO):
            duree_dechiffrage = datetime.datetime.utcnow() - debut_dechiffrage
            self.__logger.info("Duree dechiffrage : %s", duree_dechiffrage)
            date_backup = datetime.datetime.fromtimestamp(backup['date_transactions_debut'], tz=pytz.UTC)
            self.__logger.info("%s (%s) restaurer %d transactions" % (domaine, date_backup, nombre_transactions_catalogue))

        # entry = TransactionProcessEntry(data_transactions, domaine)
        # await self.__transactions_process_queue.put(entry)

        # compteur_transactions = 0
        # process_precedent = None
        # for transaction in data_transactions:
        #     compteur_transactions = compteur_transactions + 1
        #
        #     sync_traitement = compteur_transactions % RESTAURATION_BATCH_SIZE == 0
        #
        #     bypass_transaction = False
        #
        #     if bypass_transaction is False:
        #         entry = TransactionProcessEntry(data_transactions, domaine)
        #         await self.__transactions_process_queue.put(entry)
        #         # enveloppe_transaction = {'transaction': transaction, 'ack': sync_traitement}
        #         #
        #         # commande_exec = producer.executer_commande(enveloppe_transaction,
        #         #                                  domaine=domaine, action='restaurerTransaction',
        #         #                                  exchange=ConstantesMillegrilles.SECURITE_PROTEGE,
        #         #                                  nowait=not sync_traitement,
        #         #                                  timeout=120)
        #         #
        #         # # Support preparer une batch a l'avance
        #         # if sync_traitement is True:
        #         #     self.touch_activite_transactions("traiter_transactions_fichier sync debut")
        #         #     if process_precedent is not None:
        #         #         await process_precedent
        #         #         process_precedent = None
        #         #     try:
        #         #         commande_exec = asyncio.Task(commande_exec)
        #         #         await asyncio.wait_for(asyncio.shield(commande_exec), 1)
        #         #     except asyncio.TimeoutError:
        #         #         process_precedent = commande_exec
        #         #     self.touch_activite_transactions("traiter_transactions_fichier sync fin")
        #         # else:
        #         #     await commande_exec

        # if process_precedent is not None:
        #     await process_precedent

        # info_meta['nb_transactions_traitees'] = compteur_transactions
        info_meta['nb_transactions_traitees'] = nombre_transactions_traitees

        # if compteur_transactions != nombre_transactions_catalogue:
        #     self.__logger.warning("%s nombre transactions restaurees (%d) mismatch catalogue" % (compteur_transactions, nombre_transactions_catalogue))

        return info_meta

    async def send_transactions_thread(self):
        while not self.__stop_event.is_set():
            entry: TransactionProcessEntry = await self.__transactions_process_queue.get()

            if isinstance(entry, TransactionProcessEntry):
                pass
            elif isinstance(entry, TransactionsTermineEntry):
                self.__traitement_transactions_termine.set()
                continue

            producer = self.__messages_thread.get_producer()
            await producer.producer_pret().wait()

            compteur_transactions = entry.compteur
            # process_precedent = None
            # nombre_transactions = len(entry.data_transactions)
            # for transaction in entry.data_transactions:
            # compteur_transactions = compteur_transactions + 1

            sync_traitement = compteur_transactions % RESTAURATION_BATCH_SIZE == 0

            enveloppe_transaction = {'transaction': entry.transaction, 'ack': sync_traitement}
            commande_exec = producer.executer_commande(enveloppe_transaction,
                                                       domaine=entry.domaine, action='restaurerTransaction',
                                                       exchange=ConstantesMillegrilles.SECURITE_PROTEGE,
                                                       nowait=not sync_traitement,
                                                       timeout=20)

            try:
                await commande_exec
            except asyncio.TimeoutError:
                self.__logger.exception("send_transactions_thread Timeout attente sync transaction, **CONTINUE**")

            self.__compte_transactions_traitees += 1

                # # Support preparer une batch a l'avance
                # if sync_traitement:
                #     self.touch_activite_transactions("traiter_transactions_fichier sync debut")
                #     if process_precedent is not None:
                #         await process_precedent
                #         process_precedent = None
                #     try:
                #         commande_exec = asyncio.Task(commande_exec)
                #         await asyncio.wait_for(asyncio.shield(commande_exec), 1)
                #     except asyncio.TimeoutError:
                #         process_precedent = commande_exec
                #     self.touch_activite_transactions("traiter_transactions_fichier sync fin")
                # else:
                #     await commande_exec

    # async def rechiffrer_transaction_maitredescles(self, producer, transaction: dict, nowait: False):
    #     contenu_transaction = json.loads(transaction['contenu'])
    #     cle_originale = contenu_transaction['cle']
    #     cle_dechiffree = self.__clecert_ca.dechiffrage_asymmetrique(cle_originale)
    #     cles_rechiffrees = {
    #         self.__clecert_ca.fingerprint: cle_originale  # Injecter cle CA
    #     }
    #     partition = None
    #     for cert in self.__certificats_rechiffrage:
    #         cle_rechiffree, fp = cert.chiffrage_asymmetrique(cle_dechiffree)
    #         cles_rechiffrees[fp] = cle_rechiffree
    #         partition = fp
    #
    #     champs = ['header', 'iv', 'format', 'tag', 'hachage_bytes', 'domaine', 'identificateurs_document', 'signature_identite']
    #     commande_rechiffree = {
    #         'cles': cles_rechiffrees,
    #     }
    #     for champ in champs:
    #         try:
    #             commande_rechiffree[champ] = contenu_transaction[champ]
    #         except KeyError:
    #             pass  # OK, champs optionnel
    #
    #     await producer.executer_commande(commande_rechiffree, domaine='MaitreDesCles', action='sauvegarderCle',
    #                                      partition=partition, exchange=ConstantesMillegrilles.SECURITE_PRIVE, nowait=nowait,
    #                                      timeout=120)

    async def extraire_transactions(self, data: str, decipher: DecipherMgs4, domaine: str) -> int:
        loop = asyncio.get_event_loop()

        data = await loop.run_in_executor(self.__thread_pool, multibase.decode, data)       # Base 64 decode
        data = await loop.run_in_executor(self.__thread_pool, decipher.update, data)        # Dechiffrer
        data = data + decipher.finalize()   # Valider contenu dechiffre

        # liste_transactions = list()
        compteur = 0
        if len(data) > 0:
            try:
                data: bytes = await loop.run_in_executor(self.__process_pool, gzip.decompress, data)  # Decompresser en bytes (jsonl)
            except:
                self.__logger.info("extraire_transactions Decrompression GZIP echec, essayer lzma")
                data: bytes = await loop.run_in_executor(self.__process_pool, lzma.decompress, data)   # Decompresser en bytes (jsonl)

            self.__logger.debug("Transactions\n----------------------------------")
            data = await loop.run_in_executor(self.__process_pool, data.splitlines)
            for ligne in data:
                compteur += 1
                # self.__logger.debug(ligne.decode('utf-8'))
                transaction = await loop.run_in_executor(self.__process_pool, json.loads, ligne.decode('utf-8'))
                # liste_transactions.append(transaction)
                await self.__transactions_process_queue.put(TransactionProcessEntry(transaction, domaine, compteur))
            self.__logger.debug("----------------------------------\nFin Transactions")

        # return liste_transactions
        return compteur

    def preparer_certificats(self, certs: dict):
        pems = certs['pems']
        certificats_ref = certs['certificats']

        certificats = dict()
        for cert_ref in certificats_ref:
            fingerprint = cert_ref[0]
            chaine = list()
            cert_ca = None
            for cert_fp in cert_ref:
                if cert_fp.startswith('CA:'):
                    cert_ca = pems[cert_fp]
                    certificats[cert_fp] = {'chaine_pem': [cert_ca]}
                else:
                    chaine.append(pems[cert_fp])
            cert_info = {'chaine_pem': chaine, 'ca': cert_ca}
            certificats[fingerprint] = cert_info

        return certificats


def charger_cle_ca(path_cle_ca: str) -> CleCertificat:
    if path.isfile(path_cle_ca) is False:
        raise FileNotFoundError('cle CA introuvable')

    with open(path_cle_ca, 'r') as fichier:
        info_fichier = json.load(fichier)

    cert = info_fichier['racine']['certificat']
    cle = info_fichier['racine']['cleChiffree']

    print('Charger cle de MilleGrille %s pour dechiffrage' % info_fichier['idmg'])

    # Demander mot de passe (console)
    mot_de_passe = getpass.getpass(prompt="Mot de passe CA: ", stream=None)

    # Charger cle racine (dechiffree)
    try:
        clecert = CleCertificat.from_pems(cle, cert, mot_de_passe)
    except ValueError as v:
        print("Mot de passe invalide")
        raise v

    print('Cle chargee OK')

    return clecert


async def main(work_path: str, path_cle_ca: str, transactions: bool, rechiffrer: bool, domaine: Optional[str], delai: Optional[int]):
    config = dict()

    try:
        clecert = charger_cle_ca(path_cle_ca)
    except ValueError:
        print("Erreur de chargement de la cle de MilleGrille")
        return exit(1)

    extracteur = RestaurateurArchives(config, transactions, work_path, clecert, domaine, delai)

    extracteur.preparer_dechiffrage()
    if transactions is True or rechiffrer is True:
        await extracteur.preparer_mq(rechiffrer=rechiffrer)

    await extracteur.run()
