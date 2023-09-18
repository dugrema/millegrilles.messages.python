# Validateurs de messages (transactions, documents, commandes, etc.)
import binascii
import datetime
import json
import logging
import pytz

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from typing import Union

from millegrilles_messages.messages import Constantes
from millegrilles_messages.messages.EnveloppeCertificat import EnveloppeCertificat
from millegrilles_messages.messages.Hachage import ErreurHachage
from millegrilles_messages.messages.ValidateurCertificats import ValidateurCertificatCache, CertificatInconnu


class ValidateurMessage:
    """
    Validateur de messages. Verifie le hachage et la signature.
    """

    def __init__(self, validateur_certificats: ValidateurCertificatCache):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__validateur_certificats = validateur_certificats

    async def verifier(self, message: Union[bytes, str, dict],
                       utiliser_date_message=False, utiliser_idmg_message=False,
                       verifier_certificat=True) -> Union[bool, EnveloppeCertificat]:
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

        # Verifier la signature
        await verifier_signature(dict_message)

        # Verifier le hachage du contenu - si invalide, pas de raison de verifier la signature
        await self.verifier_hachage(dict_message)

        if verifier_certificat is True:
            # Valider presence de la signature en premier, certificat apres
            enveloppe_certificat = await self.__valider_certificat_message(
                message, utiliser_date_message, utiliser_idmg_message)

            return enveloppe_certificat
        else:
            return True

    async def verifier_hachage(self, message: dict) -> str:
        """
        :param message:
        :return: Hachage du message
        :raises ErreurHachage: Si le digest calcule ne correspond pas au hachage fourni
        """
        message_id = message[Constantes.MESSAGE_ID]
        message_bytes = preparer_message(message)

        # self.__logger.debug("Hacher %s" % message)
        hash_fct = hashes.Hash(hashes.BLAKE2s(32))
        hash_fct.update(message_bytes)
        hachage_calcule = binascii.hexlify(hash_fct.finalize()).decode('utf-8')

        if message_id != hachage_calcule:
            raise ErreurHachage('Erreur validation hachage')

        return message_id

    async def __valider_certificat_message(self, message, utiliser_date_message: bool, utiliser_idmg_message: bool):
        if utiliser_idmg_message:
            idmg_message = message[Constantes.MESSAGE_IDMG]
        else:
            idmg_message = None

        if utiliser_date_message:
            estampille = message[Constantes.MESSAGE_ESTAMPILLE]
            date_reference = datetime.datetime.fromtimestamp(estampille, tz=pytz.UTC)
        else:
            date_reference = None

        # Tenter d'extraire un certificat inclus dans le message - il sera utilise pour la validation
        certificats_inline = message.get('certificat')

        pubkey = message[Constantes.MESSAGE_PUBKEY]

        try:
            # Tenter de charger une version du certificat dans le cache
            enveloppe_certificat = await self.__validateur_certificats.valider_fingerprint(
                pubkey, date_reference=date_reference, idmg=idmg_message, nofetch=True)
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
            fingerprint_charge = binascii.hexlify(enveloppe_certificat.get_public_key_bytes()).decode('utf-8')
            if fingerprint_charge != pubkey:
                self.__logger.warning(
                    "Message recu avec certificat inline (%s) qui ne correspond pas au fingerprint du message %s" % (
                        fingerprint_charge, message[Constantes.MESSAGE_ID]
                    )
                )

                # Ignorer ce certificat, il n'est pas utilisable pour verifier ce message.
                raise CertificatInconnu(pubkey)
            else:
                return enveloppe_certificat
        else:
            raise CertificatInconnu(pubkey)

    @property
    def validateur_pki(self) -> ValidateurCertificatCache:
        return self.__validateur_certificats


def preparer_message(message: dict) -> bytes:
    message_hachage = list()
    champs = ['pubkey', 'estampille', 'kind', 'contenu', 'routage']
    for champ in champs:
        if message.get(champ) is not None:
            message_hachage.append(message[champ])

    # Premiere passe, converti les dates. Les nombre floats sont incorrects.
    message_str = json.dumps(
        message_hachage,
        ensure_ascii=False,   # S'assurer de supporter tous le range UTF-8
        sort_keys=True,
        separators=(',', ':')
    )

    return message_str.encode('utf-8')


async def verifier_signature(message: dict):
    # Le certificat est valide. Valider la signature du message.
    signature_bytes = binascii.unhexlify(message[Constantes.MESSAGE_SIGNATURE])
    hachage_message = binascii.unhexlify(message[Constantes.MESSAGE_ID])

    # Convertire bytes de cle publique en cle openssl
    pubkey_bytes = binascii.unhexlify(message[Constantes.MESSAGE_PUBKEY])
    pubkey = Ed25519PublicKey.from_public_bytes(pubkey_bytes)

    pubkey.verify(signature_bytes, hachage_message)

    # Signature OK, aucune exception n'a ete lancee
