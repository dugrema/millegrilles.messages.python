import datetime
import json
import logging
import multibase
import uuid
import pytz

from cryptography.hazmat.primitives import hashes

from millegrilles_messages.messages import Constantes
from millegrilles_messages.messages.Hachage import hacher
from millegrilles_messages.messages.CleCertificat import CleCertificat
from millegrilles_messages.messages.Encoders import DateFormatEncoder
from millegrilles_messages.messages.EnveloppeCertificat import CertificatExpire

VERSION_SIGNATURE = 2


class SignateurTransactionSimple:
    """ Signe une transaction avec clecert. """

    def __init__(self, clecert: CleCertificat):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__clecert = clecert

    def signer(self, dict_message):
        """
        Signe le message et retourne une nouvelle version. Ajout l'information pour le certificat.

        :param dict_message: Message a signer.
        :return: Nouvelle version du message, signee.
        """

        # S'assurer que le certificat n'est pas expire
        maintenant = datetime.datetime.now(tz=pytz.UTC)
        expiration_certificat = self.__clecert.enveloppe.not_valid_after
        if maintenant > expiration_certificat:
            raise CertificatExpire()

        # Copier la base du message et l'en_tete puisqu'ils seront modifies
        dict_message_effectif = dict_message.copy()
        en_tete = dict_message[Constantes.MESSAGE_ENTETE].copy()
        dict_message_effectif[Constantes.MESSAGE_ENTETE] = en_tete

        # Ajouter information du certification dans l'en_tete
        fingerprint_cert = self.__clecert.fingerprint
        en_tete[Constantes.MESSAGE_FINGERPRINT_CERTIFICAT] = fingerprint_cert

        signature = self._produire_signature(dict_message_effectif)
        dict_message_effectif[Constantes.MESSAGE_SIGNATURE] = signature

        return dict_message_effectif

    def _produire_signature(self, dict_message):
        # message_bytes = self.preparer_transaction_bytes(dict_message)
        message_bytes = preparer_message_bytes(dict_message)
        self.__logger.debug("Message en format json: %s" % message_bytes)

        # Hacher le message avec BLAKE2b pour supporter message de grande taille avec Ed25519
        hash_fct = hashes.Hash(hashes.BLAKE2b(64))
        hash_fct.update(message_bytes)
        hash_value = hash_fct.finalize()

        signature = self.__clecert.signer(hash_value)

        signature = bytes([VERSION_SIGNATURE]) + signature

        signature_encodee = multibase.encode('base64', signature).decode('utf-8')
        self.__logger.debug("Signature: %s" % signature_encodee)

        return signature_encodee

    @property
    def chaine_certs(self) -> list:
        return self.__clecert.enveloppe.chaine_pem()


class FormatteurMessageMilleGrilles:
    """
    Classe qui permet de creer l'entete de messages d'une MilleGrille et de signer les messages.
    Supporte aussi une contre-signature pour emission vers une MilleGrille tierce.
    """

    def __init__(self, idmg: str, signateur_transactions: SignateurTransactionSimple):
        """
        :param idmg: MilleGrille correspondant au signateur de transactions
        :param signateur_transactions: Signateur de transactions pour la MilleGrille
        """
        self.__idmg = idmg
        self.__signateur_transactions = signateur_transactions
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def signer_message(self,
                       message: dict,
                       domaine: str = None,
                       version: int = Constantes.MESSAGE_VERSION_1,
                       ajouter_chaine_certs=True,
                       action: str = None,
                       partition: str = None) -> (dict, str):
        """
        Formatte un message en ajoutant l'entete et en le signant.

        :param message: Message a signer
        :param domaine: Domaine a ajouter dans l'entete
        :param version: Version du message (depend du domaine)
        :param ajouter_chaine_certs:
        :param action:
        :param partition:
        :return: Message signe
        """

        # Ajouter identificateur unique et temps de la transaction
        uuid_transaction = uuid.uuid1()

        meta = dict()
        meta[Constantes.MESSAGE_IDMG] = self.__idmg
        meta[Constantes.MESSAGE_UUID_TRANSACTION] = "%s" % uuid_transaction
        date_courante_utc = datetime.datetime.now(tz=pytz.UTC)
        meta[Constantes.MESSAGE_ESTAMPILLE] = int(date_courante_utc.timestamp())
        meta[Constantes.MESSAGE_VERSION] = version
        if domaine is not None:
            meta[Constantes.MESSAGE_DOMAINE] = domaine
        if action is not None:
            meta[Constantes.MESSAGE_ACTION] = action
        if partition is not None:
            meta[Constantes.MESSAGE_PARTITION] = partition

        message_copy = message.copy()
        try:
            del message_copy[Constantes.MESSAGE_ENTETE]
        except KeyError:
            pass  # L'entete n'existait pas

        # Nettoyer le message, serialiser pour eliminer tous les objets
        message_bytes = preparer_message_bytes(message_copy)

        # Hacher le contenu avec SHA2-256 et signer le message avec le certificat du noeud
        self.__logger.debug("Message a hacher : %s" % message_bytes.decode('utf-8'))
        meta[Constantes.MESSAGE_HACHAGE] = hacher(message_bytes, hashing_code='blake2s-256', encoding='base64')

        # Recuperer le dict de message (deserialiser), ajouter l'entete pour signer le message
        message_copy = json.loads(message_bytes)
        message_copy[Constantes.MESSAGE_ENTETE] = meta

        message_signe = self.__signateur_transactions.signer(message_copy)

        if ajouter_chaine_certs:
            # Ajouter un element _certificats = [cert, inter, millegrilles]
            message_signe[Constantes.MESSAGE_CERTIFICAT_INCLUS] = self.__signateur_transactions.chaine_certs

        return message_signe, uuid_transaction

    @property
    def chaine_certificat(self):
        return self.__signateur_transactions.chaine_certs


def preparer_message_bytes(message: dict):
    """
            Prepare une transaction (dictionnaire) pour la signature ou la verification. Retourne des bytes.
            :return: Transaction nettoyee en bytes.
            """

    transaction_temp = dict()
    for key, value in message.items():
        if not key.startswith('_'):
            transaction_temp[key] = value

    # self._logger.debug("Message nettoye: %s" % str(transaction_temp))

    # Premiere passe, converti les dates. Les nombre floats sont incorrects.
    message_json = json.dumps(
        transaction_temp,
        ensure_ascii=False,  # S'assurer de supporter tous le range UTF-8
        cls=DateFormatEncoder
    )

    # HACK - Fix pour le decodage des float qui ne doivent pas finir par .0 (e.g. 100.0 doit etre 100)
    message_json = json.loads(message_json, parse_float=parse_float)
    message_json = json.dumps(
        message_json,
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
