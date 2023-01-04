import asyncio
import logging
import json

from cryptography.exceptions import InvalidSignature

from millegrilles_messages.messages import Constantes
from millegrilles_messages.messages.CleCertificat import CleCertificat
from millegrilles_messages.messages.FormatteurMessages import SignateurTransactionSimple, FormatteurMessageMilleGrilles
from millegrilles_messages.messages.EnveloppeCertificat import EnveloppeCertificat
from millegrilles_messages.messages.ValidateurCertificats import ValidateurCertificatCache
from millegrilles_messages.messages.ValidateurMessage import ValidateurMessage
from millegrilles_messages.messages.Hachage import ErreurHachage

PATH_CA = '/var/opt/millegrilles/configuration/pki.millegrille.cert'
PATH_CORE_CERT = '/var/opt/millegrilles/secrets/pki.core.cert'
PATH_CORE_CLE = '/var/opt/millegrilles/secrets/pki.core.cle'

logger = logging.getLogger(__name__)


def load_messages():
    with open('./test.json') as fichier:
        return json.load(fichier)


async def valider_message():
    enveloppe_ca = EnveloppeCertificat.from_file(PATH_CA)
    validateur_certificats = ValidateurCertificatCache(enveloppe_ca)
    validateur_messages = ValidateurMessage(validateur_certificats)

    clecert = CleCertificat.from_files(PATH_CORE_CLE, PATH_CORE_CERT)
    enveloppe = clecert.enveloppe
    idmg = enveloppe.idmg

    signateur = SignateurTransactionSimple(clecert)
    formatteur = FormatteurMessageMilleGrilles(idmg, signateur)

    message_signe = load_messages()

    #message_1 = {'valeur': 1, 'texte': 'Du texte.'}
    #message_1_signe, uuid_transaction = formatteur.signer_message(message_1)

    # Valider
    resultat_validation = await validateur_messages.verifier(message_signe)
    logger.debug("Resultat validation : %s", resultat_validation)

    # Corrompre contenu
    message_1_corrompu1 = message_signe.copy()
    message_1_corrompu1['mauvais'] = True
    try:
        await validateur_messages.verifier(message_1_corrompu1)
        raise Exception('fail')
    except ErreurHachage:
        logger.debug("Resultat validation ErreurHachage (OK!)")

    # Corrompre en-tete
    message_1_corrompu2 = message_signe.copy()
    message_1_corrompu2['en-tete']['mauvais'] = True
    try:
        await validateur_messages.verifier(message_1_corrompu2)
        raise Exception('fail')
    except InvalidSignature:
        logger.debug("Resultat validation InvalidSignature (OK!)")

    await validateur_certificats.entretien()


def main():
    logging.basicConfig(format=Constantes.LOGGING_FORMAT, level=logging.WARN)
    logging.getLogger(__name__).setLevel(logging.DEBUG)
    logging.getLogger('millegrilles').setLevel(logging.DEBUG)

    asyncio.run(valider_message())


if __name__ == '__main__':
    main()
