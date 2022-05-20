# Validateurs de messages (transactions, documents, commandes, etc.)
import asyncio
import datetime
import json
import logging
import pytz
import multibase

from cryptography.hazmat.primitives import hashes
from typing import Union

from millegrilles.messages import Constantes
from millegrilles.messages.EnveloppeCertificat import EnveloppeCertificat
from millegrilles.messages.FormatteurMessages import DateFormatEncoder, parse_float
from millegrilles.messages.Hachage import verifier_hachage
from millegrilles.messages.ValidateurCertificats import ValidateurCertificatCache, CertificatInconnu


class ValidateurMessage:
    """
    Validateur de messages. Verifie le hachage et la signature.
    """

    def __init__(self, validateur_certificats: ValidateurCertificatCache):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__validateur_certificats = validateur_certificats

    async def verifier(self, message: Union[bytes, str, dict], utiliser_date_message=False,
                       utiliser_idmg_message=False) -> EnveloppeCertificat:
        """
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
        message_nettoye = preparer_message(dict_message)

        # Verifier le hachage du contenu - si invalide, pas de raison de verifier la signature
        fut_hachage = self.verifier_hachage(message_nettoye)

        # Valider presence de la signature en premier, certificat apres
        signature = dict_message[Constantes.MESSAGE_SIGNATURE]
        fut_enveloppe_certificat = self.__valider_certificat_message(message, utiliser_date_message,
                                                                     utiliser_idmg_message)

        # Attendre hachage et enveloppe certificat
        resultat = await asyncio.gather(fut_hachage, fut_enveloppe_certificat)
        enveloppe_certificat = resultat[1]

        # Certificat est valide. On verifie la signature.
        await self.__verifier_signature(message_nettoye, signature, enveloppe_certificat)

        return enveloppe_certificat

    async def verifier_hachage(self, message: dict) -> str:
        """
        :param message:
        :return: Hachage du message
        :raises ErreurHachage: Si le digest calcule ne correspond pas au hachage fourni
        """
        entete = message[Constantes.MESSAGE_ENTETE]
        hachage = entete[Constantes.MESSAGE_HACHAGE]

        message_sans_entete = message.copy()
        try:
            del message_sans_entete[Constantes.MESSAGE_ENTETE]
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

    # async def verifier_signature_message(self, message: dict, enveloppe_certificat: EnveloppeCertificat):
    #     """
    #     Verifie que le message a bien ete signe par la cle specifiee
    #     :return:
    #     """
    #     signature = message['_signature']
    #
    #     message_copie = dict()
    #     for key, value in message.items():
    #         if not key.startswith('_'):
    #             message_copie[key] = value
    #
    #     # Lance une exception si echec
    #     await self.__verifier_signature(message_copie, signature, enveloppe_certificat)
    #
    #     return True

    async def __verifier_signature(self, message: dict, signature: str, enveloppe: EnveloppeCertificat):
        # Le certificat est valide. Valider la signature du message.
        signature_enveloppe = multibase.decode(signature.encode('utf-8'))
        version_signature = signature_enveloppe[0]
        signature_bytes = signature_enveloppe[1:]

        if isinstance(signature_bytes, str):
            signature_bytes = signature_bytes.encode('utf-8')

        message_bytes = json.dumps(
            message,
            ensure_ascii=False,   # S'assurer de supporter tous le range UTF-8
            sort_keys=True,
            separators=(',', ':')
        ).encode('utf-8')

        certificat = enveloppe.certificat
        cle_publique = certificat.public_key()

        if version_signature == 2:
            hash = hashes.Hash(hashes.BLAKE2b(64))
            hash.update(message_bytes)
            hash_value = hash.finalize()
            cle_publique.verify(signature_bytes, hash_value)
        else:
            raise ValueError("Version de signature non supportee : %s" % version_signature)

        # Signature OK, aucune exception n'a ete lancee

    async def __valider_certificat_message(self, message, utiliser_date_message: bool, utiliser_idmg_message: bool):
        entete = message[Constantes.MESSAGE_ENTETE]
        if utiliser_idmg_message:
            idmg_message = entete[Constantes.MESSAGE_IDMG]
        else:
            idmg_message = None

        if utiliser_date_message:
            estampille = entete[Constantes.MESSAGE_ESTAMPILLE]
            date_reference = datetime.datetime.fromtimestamp(estampille, tz=pytz.UTC)
        else:
            date_reference = None

        # Tenter d'extraire un certificat inclus dans le message - il sera utilise pour la validation
        certificats_inline = \
            message.get('_certificats') or \
            message.get('_certificat')

        entete = message[Constantes.MESSAGE_ENTETE]
        fingerprint_message = entete[Constantes.MESSAGE_FINGERPRINT_CERTIFICAT]

        try:
            # Tenter de charger une version du certificat dans le cache
            enveloppe_certificat = await self.__validateur_certificats.valider_fingerprint(
                fingerprint_message, date_reference=date_reference, idmg=idmg_message, nofetch=True)
            return enveloppe_certificat
        except CertificatInconnu:
            pass

        # Valider le certificat
        if certificats_inline is not None:
            # Nettoyage, certains certificats utilisent ; pour remplacer newline (\n)
            if isinstance(certificats_inline, str):
                certificats_inline = certificats_inline.replace(';', '\n')

            enveloppe_certificat = await self.__validateur_certificats.valider(
                certificats_inline, date_reference=date_reference, idmg=idmg_message)

            # S'assurer que le certificat correspond au fingerprint
            fingerprint_charge = enveloppe_certificat.fingerprint
            if fingerprint_charge != fingerprint_message:
                self.__logger.warning(
                    "Message recu avec certificat inline (%s) qui ne correspond pas au fingerprint du message %s" % (
                        fingerprint_charge, entete[Constantes.MESSAGE_UUID_TRANSACTION]
                    )
                )

                # Ignorer ce certificat, il n'est pas utilisable pour verifier ce message.
                raise CertificatInconnu(fingerprint_message)
            else:
                return enveloppe_certificat
        else:
            raise CertificatInconnu(fingerprint_message)

    @property
    def validateur_pki(self) -> ValidateurCertificatCache:
        return self.__validateur_certificats


def preparer_message(message: dict) -> dict:
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
    message_nettoye = json.loads(message_str, parse_float=parse_float)

    return message_nettoye
