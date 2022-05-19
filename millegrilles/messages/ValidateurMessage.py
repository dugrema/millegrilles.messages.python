# Validateurs de messages (transactions, documents, commandes, etc.)
import datetime
import json
import logging
import pytz
import multibase

from cryptography.hazmat.primitives import hashes, asymmetric
from typing import Union

from millegrilles.messages import Constantes
from millegrilles.util.ValidateursPki import ValidateurCertificatRequete, ValidateurCertificatCache, ValidateurCertificat
from millegrilles.messages.EnveloppeCertificat import EnveloppeCertificat
from millegrilles.messages.FormatteurMessages import DateFormatEncoder
from millegrilles.messages.Hachage import verifier_hachage


class ValidateurMessage:
    """
    Validateur de messages. Verifie le hachage et la signature.
    """

    def __init__(self, contexte=None, idmg=None, certificat_millegrille: str = None):
        """
        :param contexte: millegrilles.dao.Configuration.ContexteRessourcesMilleGrilles [Optionnel]
                         Permet de faire des requetes MQ pour charger les certificats par fingerprint
        :param idmg: Parametre qui permet de bloquer le validateur sur un idmg en particulier. Requis si contexte non fournis.
        """
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        if contexte is not None:
            self.__validateur = ValidateurCertificatRequete(contexte)
        elif idmg is not None:
            self.__validateur = ValidateurCertificatCache(idmg, certificat_millegrille=certificat_millegrille)
        else:
            raise ValueError("Il faut fournir le contexte ou le idmg")

        self.__signature_hash_function = hashes.SHA512

    def connecter(self):
        self.__validateur.connecter()

    def fermer(self):
        try:
            self.__validateur.fermer()
        except AttributeError:
            pass  # OK, probablement du a l'utilisation du ValidateurCertificatCache

    def entretien(self):
        """
        Invoquer regulierement pour effectuer l'entretien des elements expires.
        :return:
        """
        self.__validateur.entretien()

    def verifier(self, message: Union[bytes, str, dict], utiliser_date_message=False, utiliser_idmg_message=False) -> EnveloppeCertificat:
        """

        :param message: Message a valider.
        :param utiliser_date_message: Si True, le message est valide en utilisant en-tete.estampille comme date de
                                      validite pour le certificat plutot que la date courante.
        :param utiliser_idmg_message: Si True, utilise le idmg du message pour valider le certificat de millegrille

        :return: Enveloppe du certificat utilise pour signer le message.

        :raise millegrilles.SecuritePKI.HachageInvalide: Contenu du message est invalide.
        :raise millegrilles.SecuritePKI.CertificatInconnu: Certificat introuvable via le fingerprint du message
        :raise certvalidator.errors.PathValidationError: Certificat est invalide.
        :raise cryptography.exceptions.InvalidSignature: Signature du message est invalide.
        """
        if isinstance(message, bytes):
            dict_message = json.loads(message.decode('utf-8'))
        elif isinstance(message, str):
            dict_message = json.loads(message)
        elif isinstance(message, dict):
            dict_message = message.copy()
        else:
            raise TypeError("La transaction doit etre en format bytes, str ou dict")

        # Preparer le message pour verification du hachage et de la signature
        message_nettoye = ValidateurMessage.__preparer_message(dict_message)

        # Verifier le hachage du contenu - si invalide, pas de raison de verifier le certificat et la signature
        self.verifier_hachage(message_nettoye)

        # Hachage du contenu valide. Verifier le certificat et la signature.
        # Valider presence de la signature en premier, certificat apres
        signature = dict_message[Constantes.TRANSACTION_MESSAGE_LIBELLE_SIGNATURE]
        enveloppe_certificat = self.__valider_certificat_message(message, utiliser_date_message, utiliser_idmg_message)

        # Certificat est valide. On verifie la signature.
        self.__verifier_signature(message_nettoye, signature, enveloppe_certificat)

        return enveloppe_certificat

    def verifier_hachage(self, message: dict) -> str:
        """
        :param message:
        :return: Hachage du message
        :raises ErreurHachage: Si le digest calcule ne correspond pas au hachage fourni
        """
        entete = message[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]
        hachage = entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_HACHAGE]

        message_sans_entete = message.copy()
        try:
            del message_sans_entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]
        except KeyError:
            pass  # Ce n'est pas un message avec entete

        # message_bytes = json.dumps(message_sans_entete).encode('utf-8')
        message_bytes = json.dumps(
            message_sans_entete,
            ensure_ascii=False,  # S'assurer de supporter tous le range UTF-8
            sort_keys=True,
            separators=(',', ':')
        ).encode('utf-8')

        # Fonction de verification de hachage - lance une exception en cas de mismatch
        verifier_hachage(hachage, message_bytes)

        return hachage

    def verifier_signature_message(self, message: dict, enveloppe_certificat: EnveloppeCertificat):
        """
        Verifie que le message a bien ete signe par la cle specifiee
        :param message:
        :return:
        """
        signature = message['_signature']

        message_copie = dict()
        for key, value in message.items():
            if not key.startswith('_'):
                message_copie[key] = value

        # Lance une exception si echec
        self.__verifier_signature(message_copie, signature, enveloppe_certificat)

        return True

    def __verifier_signature(self, message: dict, signature: str, enveloppe: EnveloppeCertificat):
        # Le certificat est valide. Valider la signature du message.
        # signature_bytes = b64decode(signature)

        signature_enveloppe = multibase.decode(signature.encode('utf-8'))
        version_signature = signature_enveloppe[0]
        signature_bytes = signature_enveloppe[1:]

        message_bytes = json.dumps(
            message,
            ensure_ascii=False,   # S'assurer de supporter tous le range UTF-8
            sort_keys=True,
            separators=(',', ':')
        ).encode('utf-8')

        certificat = enveloppe.certificat
        cle_publique = certificat.public_key()

        if version_signature == 1:
            cle_publique.verify(
                signature_bytes,
                message_bytes,
                asymmetric.padding.PSS(
                    mgf=asymmetric.padding.MGF1(self.__signature_hash_function()),
                    salt_length=64  # max supporte sur iPhone asymmetric.padding.PSS.MAX_LENGTH
                ),
                self.__signature_hash_function()
            )
        elif version_signature == 2:
            hash = hashes.Hash(hashes.BLAKE2b(64))
            hash.update(message_bytes)
            hash_value = hash.finalize()
            cle_publique.verify(
                signature_bytes,
                hash_value
            )
        else:
            raise ValueError("Version de signature non supportee : %d" % version_signature)

        # Signature OK, aucune exception n'a ete lancee

    def __valider_certificat_message(self, message, utiliser_date_message: bool, utiliser_idmg_message: bool):
        entete = message[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]
        if utiliser_idmg_message:
            idmg_message = entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG]
        else:
            idmg_message = None

        if utiliser_date_message:
            estampille = entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_ESTAMPILLE]
            date_reference = datetime.datetime.fromtimestamp(estampille, tz=pytz.UTC)
        else:
            date_reference = None

        # Tenter d'extraire un certificat inclus dans le message - il sera utilise pour la validation
        certificats_inline = \
            message.get('_certificats') or \
            message.get('_certificat')

        entete = message[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]
        fingerprint_message = entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_FINGERPRINT_CERTIFICAT]

        # Valider le certificat
        if certificats_inline is not None:

            # Nettoyage, certains certificats utilisent ; pour remplacer newline (\n)
            if isinstance(certificats_inline, str):
                certificats_inline = certificats_inline.replace(';', '\n')

            enveloppe_certificat = self.__validateur.valider(
                certificats_inline, date_reference=date_reference, idmg=idmg_message)

            # S'assurer que le certificat correspond au fingerprint
            fingerprint_charge = enveloppe_certificat.fingerprint
            if fingerprint_charge != fingerprint_message:
                self.__logger.warning(
                    "Message recu avec certificat inline (%s) qui ne correspond pas au fingerprint du message %s" % (
                        fingerprint_charge, entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
                    )
                )

                # Ignorer ce certificat, il n'est pas utilisable pour verifier ce message. Tenter de charger
                # le certificat via requete MQ
                enveloppe_certificat = None
            else:
                return enveloppe_certificat

        enveloppe_certificat = self.__validateur.valider_fingerprint(
            fingerprint_message, date_reference=date_reference, idmg=idmg_message)

        return enveloppe_certificat

    @staticmethod
    def __preparer_message(message: dict) -> dict:
        message_nettoye = dict()
        for key, value in message.items():
            if not key.startswith('_'):
                message_nettoye[key] = value

        # Premiere passe, converti les dates. Les nombre floats sont incorrects.
        message_str = json.dumps(
            message_nettoye,
            ensure_ascii=False,   # S'assurer de supporter tous le range UTF-8
            cls=DateFormatEncoder
        )

        # HACK - Fix pour le decodage des float qui ne doivent pas finir par .0 (e.g. 100.0 doit etre 100)
        message_nettoye = json.loads(message_str, parse_float=ValidateurMessage.__parse_float)

        return message_nettoye

    @staticmethod
    def __parse_float(f: str):
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

    @property
    def validateur_pki(self) -> ValidateurCertificat:
        return self.__validateur
