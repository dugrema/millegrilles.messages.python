import asyncio
import datetime
import logging

from OpenSSL.crypto import X509StoreContextError

from millegrilles.messages.EnveloppeCertificat import EnveloppeCertificat
from millegrilles.messages.ValidateurCertificats import ValidateurCertificat, ValidateurCertificatRedis, IdmgInvalide

PATH_CA = '/home/mathieu/mgdev/certs/pki.millegrille'
PATH_CORE_CERT = '/home/mathieu/mgdev/certs/pki.core.cert'
PATH_CORE_KEY = '/home/mathieu/mgdev/certs/pki.core.key'

logger = logging.getLogger(__name__)


def valider_simple():
    enveloppe_ca = EnveloppeCertificat.from_file(PATH_CA)
    validateur = ValidateurCertificat(enveloppe_ca)

    with open(PATH_CORE_CERT, 'r') as fichiers:
        pem_cert = fichiers.read()

    resultat = validateur.valider(pem_cert)
    logger.debug("Resultat validation OK : %s" % resultat)

    validateur.valider(pem_cert, datetime.datetime.now())
    logger.debug("Resultat validation date OK : %s" % resultat)

    date_6mois = datetime.datetime.now() - datetime.timedelta(days=365)
    try:
        validateur.valider(pem_cert, date_6mois)
    except X509StoreContextError:
        logger.debug("Resultat validation date - 12 mois: invalide (OK!)")

    resultat = validateur.valider(pem_cert, idmg='zeYncRqEqZ6eTEmUZ8whJFuHG796eSvCTWE4M432izXrp22bAtwGm7Jf')
    logger.debug("Resultat validation idmg OK : %s" % resultat)

    try:
        validateur.valider(pem_cert, idmg="BUBBAH-GUMP")
    except IdmgInvalide:
        logger.debug("Resultat validation IDMG : invalide (OK!)")


async def valider_redis():
    # Test connexion a redis, sauvegarder cert, get par fingerprint
    enveloppe_ca = EnveloppeCertificat.from_file(PATH_CA)
    validateur = ValidateurCertificatRedis(enveloppe_ca)
    await validateur.entretien()  # Se connecte a redis

    with open(PATH_CORE_CERT, 'rb') as fichier:
        pem_bytes = fichier.read()
    enveloppe = await validateur.valider(pem_bytes)

    # Charger cert arbitraire
    fingerprint_1 = enveloppe.fingerprint
    enveloppe = await validateur.valider_fingerprint(fingerprint_1)
    logger.debug("Fingerprint %s enveloppe chargee redis : %s" % (fingerprint_1, enveloppe))


def main():
    logging.basicConfig()
    logging.getLogger(__name__).setLevel(logging.DEBUG)
    logging.getLogger('millegrilles').setLevel(logging.DEBUG)

    valider_simple()
    asyncio.run(valider_redis())


if __name__ == '__main__':
    main()
