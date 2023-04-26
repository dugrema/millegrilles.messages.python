import asyncio
import datetime
import getpass
import logging
import json
import lzma
import os

import multibase
import tarfile

from os import path, makedirs, unlink, walk
from typing import Optional

import pytz

from millegrilles_messages.backup.Configuration import ConfigurationBackup
from millegrilles_messages.messages import Constantes
from millegrilles_messages.messages.ValidateurMessage import ValidateurMessage, ValidateurCertificatCache
from millegrilles_messages.messages.EnveloppeCertificat import EnveloppeCertificat
from millegrilles_messages.messages.CleCertificat import CleCertificat
from millegrilles_messages.messages.FormatteurMessages import SignateurTransactionSimple, FormatteurMessageMilleGrilles
from millegrilles_messages.chiffrage.Mgs4 import CipherMgs4, DecipherMgs4

from millegrilles_messages.messages.MessagesThread import MessagesThread
from millegrilles_messages.messages.MessagesModule import RessourcesConsommation
from millegrilles_messages.certificats.CertificatsInstance import signer_instance_migration


PATH_MIGRER = '_MIGRER'
TAILLE_BUFFER = 64 * 1024


class MigrateurArchives:

    def __init__(self, config: dict, archive: str, source_path: str, destination_path: str, clecert_ca: CleCertificat,
                 domaine: Optional[str] = None, clecert_ca_destination: Optional[CleCertificat] = None):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__config = ConfigurationBackup()
        self.__archive = archive
        self.__source_path = source_path
        self.__destination_path = destination_path
        self.__clecert_ca = clecert_ca
        self.__clecert_ca_destination = clecert_ca_destination
        self.__domaine = domaine
        self.__clecert_migration: Optional[CleCertificat] = None

        self.__enveloppe_ca: Optional[EnveloppeCertificat] = None
        self.__formatteur: Optional[FormatteurMessageMilleGrilles] = None
        self.__validateur_certificats: Optional[ValidateurCertificatCache] = None
        self.__validateur_messages: Optional[ValidateurMessage] = None

        # Parse configuration environnement
        self.__config.parse_config(config)

        self.__migrateur_transactions: Optional[MigrateurTransactions] = None

    def preparer_dechiffrage(self):
        path_ca = self.__config.ca_pem_path
        try:
            self.__enveloppe_ca = EnveloppeCertificat.from_file(path_ca)
        except FileNotFoundError:
            self.__logger.warning("Chiffrage annule, CA introuvable (path %s)", path_ca)
            return

        # clecert = CleCertificat.from_files(self.__config.key_pem_path, self.__config.cert_pem_path)

        self.__clecert_migration = signer_instance_migration(self.__clecert_ca_destination)

        signateur = SignateurTransactionSimple(self.__clecert_migration)
        self.__formatteur = FormatteurMessageMilleGrilles(self.__clecert_migration.enveloppe.idmg, signateur)
        self.__validateur_certificats = ValidateurCertificatCache(self.__enveloppe_ca)
        self.__validateur_messages = ValidateurMessage(self.__validateur_certificats)

    async def preparer_mq(self):
        self.__migrateur_transactions = MigrateurTransactions(
            self.__formatteur, self.__config, self.__clecert_migration, self.__clecert_ca, self.__source_path,
            self.__destination_path,
            domaine=self.__domaine, clecert_ca_destination=self.__clecert_ca_destination)
        await self.__migrateur_transactions.preparer()

    async def run(self):
        if self.__archive is not None:
            self.__logger.info("Traiter archive %s" % self.__archive)
            path_archive = await self.extraire_archive()
            path_archive_dechiffree = await self.dechiffrer(path_archive)
            await self.extraire_archive_dechiffree(path_archive_dechiffree)

        if self.__migrateur_transactions is not None:
            self.__logger.info("Traiter transactions")
            await self.__migrateur_transactions.run()

    async def extraire_archive(self) -> str:
        makedirs(self.__destination_path, mode=0o755, exist_ok=True)

        path_archive = None

        with tarfile.open(self.__archive, 'r') as fichier_tar:
            tar_member = fichier_tar.next()
            while tar_member is not None:
                if tar_member.name != 'catalogue.json':
                    path_archive = path.join(self.__destination_path, tar_member.name)

                fichier_tar.extract(tar_member, self.__destination_path)
                tar_member = fichier_tar.next()

        return path_archive

    async def dechiffrer(self, path_archive: str) -> str:
        catalogue_path = path.join(self.__destination_path, 'catalogue.json')
        with open(catalogue_path, 'r') as fichier:
            catalogue = json.load(fichier)

        verifier_enveloppe = True
        try:
            if os.environ.get('VALIDATION_SKIP') is not None:
                verifier_enveloppe = False
        except KeyError:
            pass

        if verifier_enveloppe is True:
            enveloppe = await self.__validateur_messages.verifier(catalogue, utiliser_date_message=True)

        cle_dechiffree = self.__clecert_ca.dechiffrage_asymmetrique(catalogue['cle'])
        decipher = DecipherMgs4(cle_dechiffree, catalogue['header'])

        path_archive_dechiffree = '.'.join(path_archive.split('.')[:-1])
        with open(path_archive_dechiffree, 'wb') as fichier_output:
            with open(path_archive, 'rb') as fichier:
                buffer_bytes = fichier.read(TAILLE_BUFFER)
                while len(buffer_bytes) > 0:
                    data = decipher.update(buffer_bytes)
                    fichier_output.write(data)
                    buffer_bytes = fichier.read(TAILLE_BUFFER)

            data = decipher.finalize()
            fichier_output.write(data)

        print("Dechiffrage OK")

        unlink(path_archive)

        return path_archive_dechiffree

    async def extraire_archive_dechiffree(self, path_archive):
        with tarfile.open(path_archive, 'r') as tar_file:
            tar_file.extractall(self.__destination_path)
        unlink(path_archive)


class MigrateurTransactions:

    def __init__(self, formatteur: FormatteurMessageMilleGrilles, config: ConfigurationBackup,
                 clecert_migration: CleCertificat, clecert_ca: CleCertificat,
                 source_path: str, work_path: str, domaine: Optional[str],
                 clecert_ca_destination: Optional[CleCertificat]):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__formatteur = formatteur
        self.__config = config
        self.__clecert_migration = clecert_migration
        self.__clecert_ca = clecert_ca
        self.__clecert_ca_destination = clecert_ca_destination
        self.__source_path = source_path
        self.__work_path = work_path
        self.__stop_event: Optional[asyncio.Event] = None
        self.__liste_complete_event: Optional[asyncio.Event] = None
        self.__messages_thread: Optional[MessagesThread] = None
        self.__fiche: Optional[dict] = None
        self.__certificats_rechiffrage: Optional[list[EnveloppeCertificat]] = None
        self.__domaine = domaine

        self.__path_fichier_archives = path.join(work_path, 'liste.txt')
        self.__fp_fichiers_archive = None

        self.__ca_destination = EnveloppeCertificat.from_file(self.__config.ca_pem_path)

    async def preparer(self):
        makedirs(self.__work_path, mode=0o755, exist_ok=True)

        reply_res = RessourcesConsommation(self.traiter_reponse)
        self.__stop_event = asyncio.Event()
        self.__liste_complete_event = asyncio.Event()
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
        self.__logger.debug("Message recu : %s" % json.dumps(message.parsed, indent=2))

        message_parsed = message.parsed

        if self.__liste_complete_event.is_set() is False:
            # Mode recevoir liste fichiers/cles
            try:
                cles = message_parsed['cles']
                self.__logger.info("Cles recues : %s", cles)

                await asyncio.to_thread(self.conserver_liste_fichiers, cles)

            except KeyError:
                pass

            try:
                if message_parsed['complet'] is True:
                    self.__liste_complete_event.set()
            except KeyError:
                pass

    def conserver_liste_fichiers(self, cles: dict):
        for nom_fichier, cle in cles.items():
            self.__fp_fichiers_archive.write(nom_fichier + '\n')

    async def run(self):
        # Demarrer traitement messages
        await self.__messages_thread.start_async()

        tasks = [
            asyncio.create_task(self.__messages_thread.run_async()),
            asyncio.create_task(self.run_traitement_transactions()),
        ]

        # Execution de la loop avec toutes les tasks
        await asyncio.tasks.wait(tasks, return_when=asyncio.tasks.FIRST_COMPLETED)

    async def run_traitement_transactions(self):
        self.__logger.info("Attendre MQ")
        await self.__messages_thread.attendre_pret()
        self.__logger.info("MQ pret")

        self.__logger.info("Recuperer certificats maitre des cles")
        producer = self.__messages_thread.get_producer()
        idmg_local = self.__ca_destination.idmg
        reponse = await asyncio.wait_for(producer.executer_requete(
            {'idmg': idmg_local}, domaine='CoreTopologie', action='ficheMillegrille', exchange=Constantes.SECURITE_PRIVE), 10)
        self.__fiche = reponse.parsed
        cert_pem = ''.join(self.__fiche['chiffrage'].pop())
        certificat_rechiffrage = EnveloppeCertificat.from_pem(cert_pem)
        if 'maitredescles' not in certificat_rechiffrage.get_roles:
            raise ValueError('Mauvais certificat de rechiffrage recu - doit avoir role maitredescles')
        self.__certificats_rechiffrage = [certificat_rechiffrage]

        await self.traiter_fichiers()

    async def traiter_fichiers(self):
        # Faire la liste des fichiers, traiter un par un
        for root, dirs, files in walk(self.__source_path):
            for file in files:
                if file.endswith('.json.xz'):
                    nom_fichier = path.join(root, file)
                    self.__logger.debug("Traiter fichier %s", nom_fichier)
                    #print("Traiter fichier %s", nom_fichier)
                    await self.traiter_fichier(nom_fichier)

    async def traiter_fichier(self, nom_fichier: str):
        self.__logger.debug("Traiter %s" % nom_fichier)

        if self.__domaine is not None:
            domaine_fichier = nom_fichier.split('/')[-2]
            if self.__domaine != domaine_fichier:
                return  # Skip, mauvais domaine

        # Charger le fichier de backup
        self.__logger.debug("Traiter fichier de backup %s" % nom_fichier)
        with lzma.open(nom_fichier) as fichier:
            contenu_catalogue = json.load(fichier)
            self.__logger.debug("Traiter fichier %s" % contenu_catalogue)

        try:
            domaine = contenu_catalogue['domaine']
        except KeyError:
            self.__logger.error("Transaction %s n'a pas de champ domaine - ** SKIP **" % nom_fichier)
            return

        try:
            await self.traiter_transactions_fichier(nom_fichier, contenu_catalogue)
        except ValueError:
            self.__logger.exception("Erreur dechiffrage fichier %s" % nom_fichier)

    async def traiter_transactions_fichier(self, nom_fichier: str, backup: dict) -> dict:
        domaine = backup['domaine']
        nom_fichier_base = path.basename(nom_fichier)
        path_destination_domaine = path.join(self.__work_path, domaine)
        path_destination_catalogue = path.join(path_destination_domaine, nom_fichier_base)

        nombre_transactions_catalogue = backup['nombre_transactions']
        info_meta = {'domaine': domaine, 'nb_transactions_catalogue': nombre_transactions_catalogue}

        # Dechiffrer cle
        cle_dechiffree = self.__clecert_ca.dechiffrage_asymmetrique(backup['cle'])
        decipher = DecipherMgs4(cle_dechiffree, backup['header'])

        # Remapper les certificats (ajoute certificat migration)
        mapping_certificats, ancien_nouveau_mapping, remappe_certs = self.remapper_certificats(backup['certificats'])

        certificats = {
            'pems': mapping_certificats,
            'certificats': remappe_certs,
        }
        backup['certificats'] = certificats

        # Cleanup anciens elements
        del backup['_signature']
        del backup['_certificat']
        del backup['en-tete']

        # certificats = self.preparer_certificats(backup['certificats'])

        # Dechiffrer transactions
        data_transactions = await asyncio.to_thread(self.extraire_transactions, backup['data_transactions'], decipher)

        if self.__logger.isEnabledFor(logging.INFO):
            date_backup = datetime.datetime.fromtimestamp(backup['date_transactions_debut'], tz=pytz.UTC)
            self.__logger.info("%s (%s) restaurer %d transactions" % (domaine, date_backup, nombre_transactions_catalogue))

        # transactions_migrees = list()
        compteur_transactions = 0
        transactions_migrees = ''
        for transaction in data_transactions:
            transaction_migree, uuid_transaction = await self.migrer_transaction(transaction, ancien_nouveau_mapping)
            compteur_transactions += 1
            transactions_migrees += json.dumps(transaction_migree) + '\n'
            # try:
            #     # action = transaction['en-tete']['action']
            #     action = transaction['routage']['action']
            # except KeyError:
            #     pass  # OK, pas d'action
            # else:
            #     if self.__certificats_rechiffrage is not None and domaine == 'MaitreDesCles' and action == 'cle':
            #         # self.__logger.info("Rechiffrer cle")
            #         bypass_transaction = True
            #         await self.rechiffrer_transaction_maitredescles(producer, transaction, not sync_traitement)
            #
            # if bypass_transaction is False:
            #     certificat = certificats[fingerprint]
            #     transaction['certificat'] = certificat
            #
            #     enveloppe_transaction = {'transaction': transaction, 'ack': sync_traitement}
            #     # enveloppe_transaction = {'transaction': transaction}
            #
            #     await producer.executer_commande(enveloppe_transaction,
            #                                      domaine=domaine, action='restaurerTransaction',
            #                                      exchange=Constantes.SECURITE_PROTEGE,
            #                                      nowait=not sync_traitement,
            #                                      timeout=120)

        compteur_transactions = compteur_transactions
        info_meta['nb_transactions_traitees'] = compteur_transactions

        if compteur_transactions != nombre_transactions_catalogue:
            self.__logger.warning("%s nombre transactions restaurees (%d) mismatch catalogue" % (compteur_transactions, nombre_transactions_catalogue))

        # Rechiffrer les transactions
        cle_publique = self.__ca_destination.get_public_x25519()
        cipher = CipherMgs4(cle_publique)
        transactions_migrees = lzma.compress(transactions_migrees.encode('utf-8'))
        transactions_migrees = cipher.update(transactions_migrees)
        transactions_migrees += cipher.finalize()
        info_dechiffrage = cipher.get_info_dechiffrage(self.__certificats_rechiffrage)

        backup['cle'] = info_dechiffrage['cle']
        backup['data_hachage_bytes'] = info_dechiffrage['hachage_bytes']
        backup['header'] = info_dechiffrage['header']
        transactions_migrees = multibase.encode('base64', transactions_migrees).decode('utf-8')
        backup['data_transactions'] = transactions_migrees

        # Signer le catalogue
        catalogue_signe, uuid_transaction = self.__formatteur.signer_message(2, backup, ajouter_chaine_certs=True, domaine='Backup', action='backupTransactions')
        makedirs(path_destination_domaine, 0o755, exist_ok=True)
        with lzma.open(path_destination_catalogue, 'wb') as fichier:
            catalogue_signe = json.dumps(catalogue_signe).encode('utf-8')
            fichier.write(catalogue_signe)

        return backup

    def remapper_certificats(self, backup_certificats: dict):
        """
        Converti le hachage des certificats vers le format courant
        :param certificats:
        :return:
        """
        nouveau_mapping = dict()
        ancien_nouveau_mapping = dict()

        for ancien_fingerprint, cert_pem in backup_certificats['pems'].items():
            cert = EnveloppeCertificat.from_pem(cert_pem)
            nouveau_fingerprint = cert.fingerprint
            nouveau_mapping[nouveau_fingerprint] = cert_pem
            ancien_nouveau_mapping[ancien_fingerprint] = nouveau_fingerprint

        # Ajouter le certificat de migration
        nouveau_mapping[self.__clecert_migration.fingerprint] = self.__clecert_migration.enveloppe.certificat_pem

        # Detecter changement de IDMG
        if self.__clecert_ca.enveloppe.idmg != self.__ca_destination.idmg:
            # Ajouter certificat CA de l'ancienne MilleGrille
            ca_fingerprint = 'CA:%s:%s' % (self.__clecert_ca.enveloppe.idmg, self.__clecert_ca.fingerprint)
            nouveau_mapping[ca_fingerprint] = self.__clecert_ca.enveloppe.certificat_pem
        else:
            ca_fingerprint = None

        remappe_certs = [
            [self.__clecert_migration.fingerprint]  # Certificat de migration, chaine a un seul cert
        ]
        for cert in backup_certificats['certificats']:
            cert_remappe = [ancien_nouveau_mapping[f] for f in cert]
            if ca_fingerprint is not None:
                cert_remappe.append(ca_fingerprint)
            remappe_certs.append(cert_remappe)


        return nouveau_mapping, ancien_nouveau_mapping, remappe_certs

    async def migrer_transaction(self, transaction: dict, ancien_nouveau_mapping_fingerprints: dict):

        # Detecter format transaction
        if transaction.get('en-tete'):
            # Ancien format avec en-tete/_signature (pre 2023.5)
            return await self.migrer_pre_2023_5(transaction, ancien_nouveau_mapping_fingerprints)
        else:
            # Plus recent format
            return await self.migrer_courant(transaction, ancien_nouveau_mapping_fingerprints)

    async def migrer_pre_2023_5(self, transaction: dict, ancien_nouveau_mapping_fingerprints: dict):
        entete = transaction['en-tete']

        contenu_dict = dict()
        for key, value in transaction.items():
            if key != 'en-tete' and key.startswith('_') is False:
                contenu_dict[key] = value

        nouvelle_pubkey = ancien_nouveau_mapping_fingerprints[entete['fingerprint_certificat']]

        pre_migration = {
            'id': entete['uuid_transaction'],
            'pubkey': nouvelle_pubkey,
            'estampille': entete['estampille'],
        }

        # Verifier si on fait une migration vers une MilleGrille differente
        if entete['idmg'] != self.__ca_destination.idmg:
            pre_migration['idmg'] = entete['idmg']

        # Signer avec certificat de migration
        transaction_migree = self.__formatteur.signer_message(
            7, contenu_dict, ajouter_chaine_certs=False, pre_migration=pre_migration,
            domaine=entete.get('domaine'), action=entete.get('action'), partition=entete.get('partition')
        )

        self.__logger.debug("Transaction migree %s", transaction_migree)
        return transaction_migree

    async def migrer_courant(self, transaction: dict, ancien_nouveau_mapping_fingerprints: dict):
        raise NotImplementedError('todo')

    async def rechiffrer_transaction_maitredescles(self, producer, transaction: dict, nowait: False):
        cle_originale = transaction['cle']
        cle_dechiffree = self.__clecert_ca.dechiffrage_asymmetrique(cle_originale)
        cles_rechiffrees = {
            self.__clecert_ca.fingerprint: cle_originale  # Injecter cle CA
        }
        partition = None
        for cert in self.__certificats_rechiffrage:
            cle_rechiffree, fp = cert.chiffrage_asymmetrique(cle_dechiffree)
            cles_rechiffrees[fp] = cle_rechiffree
            partition = fp

        champs = ['header', 'iv', 'format', 'tag', 'hachage_bytes', 'domaine', 'identificateurs_document', 'signature_identite']
        commande_rechiffree = {
            'cles': cles_rechiffrees,
        }
        for champ in champs:
            try:
                commande_rechiffree[champ] = transaction[champ]
            except KeyError:
                pass  # OK, champs optionnel

        await producer.executer_commande(commande_rechiffree, domaine='MaitreDesCles', action='sauvegarderCle',
                                         partition=partition, exchange=Constantes.SECURITE_PRIVE, nowait=nowait,
                                         timeout=120)

    def extraire_transactions(self, data: str, decipher: DecipherMgs4):
        data = multibase.decode(data)       # Base 64 decode
        data = decipher.update(data)        # Dechiffrer
        data = data + decipher.finalize()   # Valider contenu dechiffre

        liste_transactions = list()
        if len(data) > 0:
            data: bytes = lzma.decompress(data)   # Decompresser en bytes (jsonl)

            for ligne in data.splitlines():
                transaction = json.loads(ligne.decode('utf-8'))
                liste_transactions.append(transaction)

        return liste_transactions

    def preparer_certificats(self, certs: dict):
        pems = certs['pems']
        certificats_ref = certs['certificats']

        certificats = dict()
        for cert_ref in certificats_ref:
            fingerprint = cert_ref[0]
            chaine = list()
            for cert_fp in cert_ref:
                chaine.append(pems[cert_fp])
            certificats[fingerprint] = chaine

        return certificats


def charger_cle_ca(path_cle_ca: str, prompt="Mot de passe CA: ") -> CleCertificat:
    if path.isfile(path_cle_ca) is False:
        raise FileNotFoundError('cle CA introuvable')

    with open(path_cle_ca, 'r') as fichier:
        info_fichier = json.load(fichier)

    cert = info_fichier['racine']['certificat']
    cle = info_fichier['racine']['cleChiffree']

    print('Charger cle de MilleGrille %s pour dechiffrage' % info_fichier['idmg'])

    # Demander mot de passe (console)
    mot_de_passe = getpass.getpass(prompt=prompt, stream=None)

    # Charger cle racine (dechiffree)
    try:
        clecert = CleCertificat.from_pems(cle, cert, mot_de_passe)
    except ValueError as v:
        print("Mot de passe invalide")
        raise v

    print('Cle chargee OK')

    return clecert


async def main(archive: str, source_path: str, destination_path: str, path_cle_ca: str, domaine: Optional[str] = None,
               path_cle_ca_dest: Optional[str] = None):
    config = dict()

    try:
        clecert = charger_cle_ca(path_cle_ca)
    except ValueError:
        print("Erreur de chargement de la cle de MilleGrille (1)")
        return exit(1)

    if path_cle_ca_dest is not None:
        try:
            clecert_dest = charger_cle_ca(path_cle_ca_dest, prompt="Mot de passe CA destination : ")
        except ValueError:
            print("Erreur de chargement de la cle de MilleGrille destination (2)")
            return exit(2)
    else:
        clecert_dest = None

    extracteur = MigrateurArchives(config, archive, source_path, destination_path, clecert, domaine, clecert_dest)

    extracteur.preparer_dechiffrage()
    await extracteur.preparer_mq()

    await extracteur.run()
