import asyncio
import datetime
import logging

from asyncio import Event
from asyncio.exceptions import TimeoutError
from OpenSSL.crypto import X509StoreContextError

from millegrilles_messages.messages.EnveloppeCertificat import EnveloppeCertificat
from millegrilles_messages.messages.ValidateurCertificats import ValidateurCertificat, ValidateurCertificatRedis, IdmgInvalide

from millegrilles_messages.messages.MessagesThread import MessagesThread
from millegrilles_messages.messages.MessagesModule import RessourcesConsommation

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
    # fingerprint_1 = enveloppe.fingerprint
    fingerprint_1 = 'mEiBvEkcpY4CKAfjhjoR0VVM74JCW7TrOqsY8daSbGNQKGA'
    enveloppe = await validateur.valider_fingerprint(fingerprint_1)
    logger.debug("Fingerprint %s enveloppe chargee redis : %s" % (fingerprint_1, enveloppe))


async def valider_systeme():
    # Test requete MQ pour charger certificat inconnu
    stop_event = Event()
    reply_res = RessourcesConsommation(callback_reply_q)

    messages_thread = MessagesThread(stop_event)
    messages_thread.set_reply_ressources(reply_res)

    # Demarrer traitement messages
    await messages_thread.start_async()

    tasks = [
        asyncio.create_task(messages_thread.run_async()),
        asyncio.create_task(run_tests_mq(messages_thread)),
    ]

    # Execution de la loop avec toutes les tasks
    await asyncio.tasks.wait(tasks, return_when=asyncio.tasks.FIRST_COMPLETED)

    logger.info("Fin main()")


async def run_tests_mq(messages_thread):
    wait_event = Event()

    try:
        await asyncio.wait_for(wait_event.wait(), 1)
    except TimeoutError:
        pass

    validateur = messages_thread.get_validateur_certificats()

    # Charger cert arbitraire
    fingerprint_1 = 'z2i3XjxFX5BHaDZMKjg2xN138eMhkucXvxM4c5CSU9h85rn452C'
    # fingerprint_1 = 'mEiBvEkcpY4CKAfjhjoR0VVM74JCW7TrOqsY8daSbGNQKGA'
    enveloppe = await validateur.valider_fingerprint(fingerprint_1)
    logger.debug("Fingerprint %s enveloppe chargee redis : %s" % (fingerprint_1, enveloppe))

    try:
        await asyncio.wait_for(wait_event.wait(), 30)
    except TimeoutError:
        pass



async def callback_reply_q(message, module_messages):
    pass


def main():
    logging.basicConfig()
    logging.getLogger(__name__).setLevel(logging.DEBUG)
    logging.getLogger('millegrilles').setLevel(logging.DEBUG)

    #valider_simple()
    #asyncio.run(valider_redis())
    asyncio.run(valider_systeme())


if __name__ == '__main__':
    main()
