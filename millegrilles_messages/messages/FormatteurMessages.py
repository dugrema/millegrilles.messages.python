import binascii
import datetime
import gzip
import json
import logging
import multibase
import uuid
import pytz

from typing import Union, Optional

from cryptography.hazmat.primitives import hashes

from millegrilles_messages.chiffrage.SignatureDomaines import SignatureDomaines
from millegrilles_messages.messages import Constantes
from millegrilles_messages.messages.CleCertificat import CleCertificat
from millegrilles_messages.messages.EnveloppeCertificat import EnveloppeCertificat

VERSION_SIGNATURE = 2


class SignateurTransactionSimple:
    """ Signe une transaction avec clecert. """

    def __init__(self, clecert: CleCertificat):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__clecert = clecert

    @property
    def clecert(self) -> CleCertificat:
        return self.__clecert

    def signer(self, message: dict):
        """
        Signe le message. Ajout l'information pour le certificat. Le id (hachage) doit deja etre present.

        :param hash_value: Valeur a signer.
        :return: Message signe.
        """

        if isinstance(message, dict) is False:
            raise TypeError("Message doit etre un dict")

        hachage = binascii.unhexlify(message['id'])  # Echec si champ id absent (hachage doit etre deja calcule)

        # # S'assurer que le certificat n'est pas expire
        # maintenant = datetime.datetime.now(tz=pytz.UTC)
        # expiration_certificat = self.__clecert.enveloppe.not_valid_after
        # if maintenant > expiration_certificat:
        #     raise CertificatExpire()

        # # Copier la base du message et l'en_tete puisqu'ils seront modifies
        # dict_message_effectif = dict_message.copy()
        # en_tete = dict_message[Constantes.MESSAGE_ENTETE].copy()
        # dict_message_effectif[Constantes.MESSAGE_ENTETE] = en_tete

        # Ajouter information du certification dans l'en_tete
        # fingerprint_cert = self.__clecert.fingerprint
        # en_tete[Constantes.MESSAGE_FINGERPRINT_CERTIFICAT] = fingerprint_cert

        # signature = self._produire_signature(dict_message_effectif)

        signature = self.signer_hachage(hachage)
        message[Constantes.MESSAGE_SIGNATURE] = binascii.hexlify(signature).decode('utf-8')
        return message

    def signer_hachage(self, hash_value: Union[str, bytes]) -> bytes:
        """
        Signe le hachage.

        :param hash_value: Valeur a signer.
        :return: Signature (bytes)
        """

        if isinstance(hash_value, str):
            # Decoder hachage (hex) en bytes
            hash_value = binascii.unhexlify(hash_value)
        elif isinstance(hash_value, bytes) is False:
            raise TypeError('Hachage doit etre str ou bytes')

        return self.__clecert.signer(hash_value)

    # def _produire_signature(self, dict_message):
    #     # message_bytes = self.preparer_transaction_bytes(dict_message)
    #     message_bytes = preparer_message_bytes(dict_message)
    #     self.__logger.debug("Message en format json: %s" % message_bytes)
    #
    #     # Hacher le message avec BLAKE2b pour supporter message de grande taille avec Ed25519
    #     hash_fct = hashes.Hash(hashes.BLAKE2s(64))
    #     hash_fct.update(message_bytes)
    #     hash_value = hash_fct.finalize()
    #
    #     signature = self.__clecert.signer(hash_value)
    #
    #     signature = bytes([VERSION_SIGNATURE]) + signature
    #
    #     signature_encodee = multibase.encode('base64', signature).decode('utf-8')
    #     self.__logger.debug("Signature: %s" % signature_encodee)
    #
    #     return signature_encodee

    @property
    def chaine_certs(self) -> list:
        return self.__clecert.enveloppe.chaine_pem()

    @property
    def pubkey(self) -> bytes:
        return self.__clecert.enveloppe.get_public_key_bytes()


class FormatteurMessageMilleGrilles:
    """
    Classe qui permet de creer l'entete de messages d'une MilleGrille et de signer les messages.
    Supporte aussi une contre-signature pour emission vers une MilleGrille tierce.
    """

    def __init__(self, idmg: str, signateur_transactions: SignateurTransactionSimple, ca: Optional[EnveloppeCertificat]):
        """
        :param idmg: MilleGrille correspondant au signateur de transactions
        :param signateur_transactions: Signateur de transactions pour la MilleGrille
        """
        self.__idmg = idmg
        self.__signateur_transactions = signateur_transactions
        self.__enveloppe_ca = ca
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    @property
    def clecert(self) -> CleCertificat:
        return self.__signateur_transactions.clecert

    def signer_message(self,
                       kind: int,
                       message: dict,
                       domaine: str = None,
                       ajouter_chaine_certs=True,
                       action: str = None,
                       partition: str = None,
                       pre_migration: dict = None) -> (dict, str):
        """
        Formatte un message en ajoutant l'entete et en le signant.

        :param kind: Type de message
        :param message: Message a signer
        :param domaine: Domaine a ajouter dans l'entete
        :param version: Version du message (depend du domaine)
        :param ajouter_chaine_certs:
        :param action:
        :param partition:
        :return: Message signe
        """
        if isinstance(kind, int) is False:
            raise TypeError("Kind doit etre un int")

        # Ajouter identificateur unique et temps de la transaction
        #uuid_transaction = uuid.uuid1()

        # Calculer l'identificateur unique

        date_courante_utc = datetime.datetime.now(tz=pytz.UTC)
        estampille = int(date_courante_utc.timestamp())

        dechiffrage = None
        origine = None

        if kind == Constantes.KIND_REPONSE_CHIFFREE:
            message_contenu = message['contenu']  # Copier directement contenu chiffre
            dechiffrage = message['dechiffrage']
            try:
                del message['origine']
            except KeyError:
                pass
        elif kind == Constantes.KIND_COMMANDE_INTER_MILLEGRILLE:
            message_contenu = message['contenu']  # Copier directement contenu chiffre
            dechiffrage = message['dechiffrage']
            origine = message['origine']
        else:
            message_contenu = json.dumps(
                message,
                ensure_ascii=False,  # S'assurer de supporter tous le range UTF-8
                sort_keys=True,
                separators=(',', ':')
            )

        pubkey = binascii.hexlify(self.__signateur_transactions.pubkey).decode('utf-8')

        message_hachage = [
            pubkey,
            estampille,
            kind,
            message_contenu,
        ]
        enveloppe_message = {
            'pubkey': pubkey,  # Cle publique du certificat
            'estampille': estampille,
            'kind': kind,
            'contenu': message_contenu,
        }
        if kind in [1, 2, 3, 5, 7, 8]:
            # Ajouter information de routage
            routage = dict()
            if action is not None:
                routage['action'] = action
            if domaine is not None:
                routage['domaine'] = domaine
            if partition is not None:
                routage['partition'] = partition
            enveloppe_message['routage'] = routage
            message_hachage.append(routage)
        if kind in [6]:
            enveloppe_message['dechiffrage'] = dechiffrage
            message_hachage.append(dechiffrage)
        if kind in [7]:
            enveloppe_message['pre-migration'] = pre_migration
            message_hachage.append(pre_migration)
        if kind in [8]:
            enveloppe_message['origine'] = origine
            message_hachage.append(origine)
            enveloppe_message['dechiffrage'] = dechiffrage
            message_hachage.append(dechiffrage)

        # Preparer le contenu a hacher
        message_hachage_json = json.dumps(
            message_hachage,
            ensure_ascii=False,  # S'assurer de supporter tous le range UTF-8
            sort_keys=True,
            separators=(',', ':')
        )
        message_bytes = bytes(message_hachage_json, 'utf-8')

        # Hacher le contenu
        # self.__logger.debug("Hacher \n%s", message_hachage_json)
        hash_fct = hashes.Hash(hashes.BLAKE2s(32))
        hash_fct.update(message_bytes)
        message_id = binascii.hexlify(hash_fct.finalize()).decode('utf-8')
        enveloppe_message['id'] = message_id

        message_signe = self.__signateur_transactions.signer(enveloppe_message)

        if ajouter_chaine_certs:
            # Ajouter un element _certificats = [cert, inter, millegrilles]
            message_signe[Constantes.MESSAGE_CERTIFICAT_INCLUS] = self.__signateur_transactions.chaine_certs

        return message_signe, message_id

    async def chiffrer_message(
            self, cles_chiffrage: list[EnveloppeCertificat], kind: int, message: dict, domaine: str = None,
            action: str = None, partition: str = None, cle_secrete: bytes = None) -> (dict, str):

        if self.__enveloppe_ca is None:
            raise Exception("Enveloppe CA non chargee")

        # Importer CipherMgs4 ici pour eviter une reference circulaire
        from millegrilles_messages.chiffrage.Mgs4 import CipherMgs4, CipherMgs4WithSecret

        origine = self.__idmg

        contenu = json.dumps(message).encode('utf-8')
        contenu = gzip.compress(contenu)

        # Chiffrer et compresser le contenu
        nouvelle_cle = cle_secrete is None
        if nouvelle_cle:
            public_x25519 = self.__enveloppe_ca.get_public_x25519()
            cipher = CipherMgs4(public_x25519)
            cle_secrete = cipher.cle_secrete
        else:
            cipher = CipherMgs4WithSecret(cle_secrete)

        contenu = cipher.update(contenu)
        contenu += cipher.finalize()
        if nouvelle_cle:
            meta_dechiffrage = cipher.get_info_dechiffrage(cles_chiffrage)
            domaines_signature = SignatureDomaines.signer_domaines(
                cle_secrete, [domaine], meta_dechiffrage['cle'][1:])
            domaines_signature_dict = domaines_signature.to_dict()
        else:
            domaines_signature_dict = None
            meta_dechiffrage = None

        contenu = multibase.encode('base64', contenu).decode('utf-8')[1:]  # Retirer 'm' multibase, on veut juste base64 no pad

        dechiffrage = {
            'format': 'mgs4',
            'nonce': multibase.encode('base64', cipher.header).decode('utf-8')[1:],
            'compression': 'gzip',
        }

        if meta_dechiffrage:
            dechiffrage['cles'] = meta_dechiffrage['cles']
        if domaines_signature_dict:
            dechiffrage['signature']: domaines_signature_dict

        payload = {
            'dechiffrage': dechiffrage,
            'origine': origine,
            'contenu': contenu,
        }

        message_signe, message_id = self.signer_message(kind, payload, domaine, True, action, partition)

        return message_signe, message_id

    @property
    def chaine_certificat(self):
        return self.__signateur_transactions.chaine_certs


def preparer_message_bytes(message: dict):
    """
            Prepare une transaction (dictionnaire) pour la signature ou la verification. Retourne des bytes.
            :return: Transaction nettoyee en bytes.
            """

    # transaction_temp = dict()
    # for key, value in message.items():
    #     if not key.startswith('_'):
    #         transaction_temp[key] = value
    #
    # # self._logger.debug("Message nettoye: %s" % str(transaction_temp))
    #
    # # Premiere passe, converti les dates. Les nombre floats sont incorrects.
    # message_json = json.dumps(
    #     transaction_temp,
    #     ensure_ascii=False,  # S'assurer de supporter tous le range UTF-8
    #     cls=DateFormatEncoder
    # )
    #
    # # HACK - Fix pour le decodage des float qui ne doivent pas finir par .0 (e.g. 100.0 doit etre 100)
    # message_json = json.loads(message_json, parse_float=parse_float)
    message_json = json.dumps(
        message,
        ensure_ascii=False,  # S'assurer de supporter tous le range UTF-8
        sort_keys=True,
        separators=(',', ':')
    )

    message_bytes = bytes(message_json, 'utf-8')

    return message_bytes


def parse_float(f: str):
    """
    Permet de transformer les nombre floats qui finissent par .0 en entier. Requis pour interoperabilite avec
    la verification (hachage, signature) en JavaScript qui fait cette conversion implicitement.
    :param f:
    :return:
    """
    val_float = float(f)
    val_int = int(val_float)
    if val_int == val_float:
        return val_int
    return val_float
