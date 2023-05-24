import asyncio
import datetime
import gzip
import json
import logging
import multibase
import base64

from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from millegrilles_messages.messages import Constantes
from millegrilles_messages.chiffrage.Mgs4 import generer_cle_secrete, CipherMgs4WithSecret
from millegrilles_messages.messages.EnveloppeCertificat import EnveloppeCertificat
from millegrilles_messages.messages.MessagesModule import MessageProducerFormatteur
from millegrilles_messages.chiffrage.ChiffrageUtils import generer_signature_identite_cle


class EmetteurNotifications:

    def __init__(self, enveloppe_ca: EnveloppeCertificat, champ_from: Optional[str]):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__from = champ_from
        self.__enveloppe_ca = enveloppe_ca

        # Information de chiffrage
        self.__cle_secrete: Optional[bytes] = None
        self.__public_peer_x25519: Optional[X25519PublicKey] = None
        self.__ref_hachage_bytes: Optional[str] = None

        self.__commande_cle: Optional[dict] = None
        self.__cle_transmise = False

        # Preparer la cle pour les notifications systeme (proprietaire)
        self.generer_cle_secrete()

    def generer_cle_secrete(self):
        self.__public_peer_x25519, self.__cle_secrete = generer_cle_secrete(self.__enveloppe_ca.get_public_x25519())

    async def get_certificats_maitredescles(self, producer: MessageProducerFormatteur):
        """
        Prepare a emettre des notifications
        :return:
        """
        # Recuperer certificats de maitre des cles
        action = 'certMaitreDesCles'
        requete = {}
        reponse = await producer.executer_requete(
            requete, 'MaitreDesCles', action=action, exchange=Constantes.SECURITE_PUBLIC)
        parsed = reponse.parsed
        certificat = parsed['certificat']
        enveloppe = EnveloppeCertificat.from_pem(certificat)
        roles = enveloppe.get_roles
        if 'maitredescles' not in roles:
            raise Exception('Mauvais certificat maitredescles recu (role incorrect)')
        return [self.__enveloppe_ca, enveloppe]

    async def emettre_notification(
            self,
            producer: MessageProducerFormatteur,
            contenu: str,
            subject: Optional[str],
            niveau='info',
            destinataires: Optional[list] = None
    ):
        event_pret = producer.producer_pret()
        if event_pret.is_set() is False:
            await asyncio.wait_for(event_pret.wait(), 3)

        message_chiffre = await self.preparer_contenu(producer, contenu, subject)

        expiration = datetime.datetime.utcnow() + datetime.timedelta(days=7)

        commande = {
            'expiration': round(expiration.timestamp()),
            'niveau': niveau,
            'message': message_chiffre,
        }

        if destinataires is not None:
            commande['destinataires'] = destinataires

        attachements = None
        if self.__cle_transmise is False:
            # Transmettre la cle pour dechiffrer les notifications
            attachements = {'cle': self.__commande_cle}

        try:
            reponse = await producer.executer_commande(
                commande, 'Messagerie', 'notifier', exchange=Constantes.SECURITE_PUBLIC,
                timeout=3, attachements=attachements)

            # Commande recue et traitee, on ne retransmet plus la cle
            if reponse.parsed.get('ok') is True:
                self.__cle_transmise = True

        except asyncio.TimeoutError:
            self.__logger.info("Timeout emission notification")

    async def preparer_contenu(self, producer, contenu: str, subject: Optional[str]):
        message = {'content': contenu, 'format': 'html', 'version': 1}

        if self.__from is None:
            message['from'] = 'Systeme'
        else:
            message['from'] = self.__from

        if subject is not None:
            message['subject'] = subject

        self.__logger.debug("Contenu notification a preparer : %s" % message)

        # message, uuid_transaction = await producer.signer(message, Constantes.KIND_DOCUMENT)
        # del message['certificat']

        message_compresse = gzip.compress(json.dumps(message).encode('utf-8'))

        # Chiffrer le contenu
        # self.__logger.debug("Cle secrete : %s" % list(self.__cle_secrete))
        cipher = CipherMgs4WithSecret(self.__cle_secrete)
        format_chiffrage = 'mgs4'
        domaine = 'Messagerie'
        message_chiffre = cipher.update(message_compresse)
        message_chiffre += cipher.finalize()
        # message_chiffre = multibase.encode('base64', message_chiffre).decode('utf-8')
        message_chiffre = base64.b64encode(message_chiffre).decode('utf-8')
        # Retirer padding a la fin (=)
        message_chiffre = message_chiffre.replace('=', '')

        if self.__commande_cle is None:
            # Conserver commande cle comme reference future
            enveloppes = await self.get_certificats_maitredescles(producer)
            params_dechiffrage = cipher.params_dechiffrage(self.__public_peer_x25519, enveloppes)

            identificateurs_document = {'notification': 'true'}
            params_dechiffrage['identificateurs_document'] = identificateurs_document
            params_dechiffrage['domaine'] = domaine
            params_dechiffrage['format'] = 'mgs4'

            self.__logger.debug("Cle secrete : %s" % list(self.__cle_secrete))

            signature = generer_signature_identite_cle(
                self.__cle_secrete,
                domaine,
                identificateurs_document,
                params_dechiffrage['hachage_bytes']
            )
            params_dechiffrage['signature_identite'] = signature

            partition = params_dechiffrage['partition']

            # Signer la commande de cle
            commande_signee, message_id = await producer.signer(
                params_dechiffrage, Constantes.KIND_COMMANDE, 'MaitreDesCles', 'sauvegarderCle', partition)
            commande_signee['attachements'] = {'partition': partition}
            self.__commande_cle = commande_signee

        else:
            # Generer params sans cles de dechiffrage (commande cle secrete deja generee)
            params_dechiffrage = cipher.params_dechiffrage(self.__public_peer_x25519, list())

        contenu_commande_cle = json.loads(self.__commande_cle['contenu'])

        dechiffrage = {
            'cle_id': contenu_commande_cle['hachage_bytes'],
            'header': params_dechiffrage['header'],
            'format': format_chiffrage,
        }

        message_a_signer = {
            'contenu': message_chiffre,
            'dechiffrage': dechiffrage,
            'origine': self.__enveloppe_ca.idmg
        }

        message_signe, message_id = await producer.signer(
            message_a_signer, Constantes.KIND_COMMANDE_INTER_MILLEGRILLE, 'Messagerie', 'nouveauMessage')
        del message_signe['certificat']

        return message_signe
