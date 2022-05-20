import logging
import asyncio

from cryptography.exceptions import InvalidSignature

from millegrilles.messages import Constantes
from millegrilles.messages.CleCertificat import CleCertificat
from millegrilles.messages.FormatteurMessages import SignateurTransactionSimple, FormatteurMessageMilleGrilles
from millegrilles.messages.EnveloppeCertificat import EnveloppeCertificat
from millegrilles.messages.ValidateurCertificats import ValidateurCertificat
from millegrilles.messages.ValidateurMessage import ValidateurMessage
from millegrilles.messages.Hachage import ErreurHachage

PATH_CA = '/home/mathieu/mgdev/certs/pki.millegrille'
PATH_CORE_CERT = '/home/mathieu/mgdev/certs/pki.core.cert'
PATH_CORE_CLE = '/home/mathieu/mgdev/certs/pki.core.key'

logger = logging.getLogger(__name__)


async def valider_message():
    enveloppe_ca = EnveloppeCertificat.from_file(PATH_CA)
    validateur_certificats = ValidateurCertificat(enveloppe_ca)
    validateur_messages = ValidateurMessage(validateur_certificats)

    clecert = CleCertificat.from_files(PATH_CORE_CLE, PATH_CORE_CERT)
    enveloppe = clecert.enveloppe
    idmg = enveloppe.idmg

    signateur = SignateurTransactionSimple(clecert)
    formatteur = FormatteurMessageMilleGrilles(idmg, signateur)

    message_1 = {'valeur': 1, 'texte': 'Du texte.'}
    message_1_signe, uuid_transaction = formatteur.signer_message(message_1)

    # Valider
    resultat_validation = await validateur_messages.verifier(message_1_signe)
    logger.debug("Resultat validation : %s", resultat_validation)

    # Corrompre contenu
    message_1_corrompu1 = message_1_signe.copy()
    message_1_corrompu1['mauvais'] = True
    try:
        await validateur_messages.verifier(message_1_corrompu1)
        raise Exception('fail')
    except ErreurHachage:
        logger.debug("Resultat validation ErreurHachage (OK!)")

    # Corrompre en-tete
    message_1_corrompu2 = message_1_signe.copy()
    message_1_corrompu2['en-tete']['mauvais'] = True
    try:
        await validateur_messages.verifier(message_1_corrompu2)
        raise Exception('fail')
    except InvalidSignature:
        logger.debug("Resultat validation InvalidSignature (OK!)")


def main():
    logging.basicConfig(format=Constantes.LOGGING_FORMAT, level=logging.WARN)
    logging.getLogger(__name__).setLevel(logging.DEBUG)
    logging.getLogger('millegrilles').setLevel(logging.DEBUG)

    asyncio.run(valider_message())


if __name__ == '__main__':
    main()
