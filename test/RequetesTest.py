import asyncio
import logging

from asyncio.exceptions import TimeoutError
from threading import Event
from pika.exchange_type import ExchangeType

from millegrilles_messages.messages import Constantes
from millegrilles_messages.messages.MessagesThread import MessagesThread
from millegrilles_messages.messages.MessagesModule import RessourcesConsommation, ExchangeConfiguration

logger = logging.getLogger(__name__)

LOGGING_FORMAT = '%(asctime)s %(threadName)s %(levelname)s: %(message)s'


async def main():
    logger.info("Debut main()")
    stop_event = Event()

    # Preparer resources consumer
    reply_res = RessourcesConsommation(callback_reply_q)
    # q1 = RessourcesConsommation(callback_q_1, 'CoreBackup/tada')
    # q1.ajouter_rk('3.protege', 'commande.CoreBackup.m1')
    # q1.ajouter_rk('2.prive', 'commande.CoreBackup.m2')

    messages_thread = MessagesThread(stop_event)
    # messages_thread.ajouter_exchange(exchange_1)
    messages_thread.set_reply_ressources(reply_res)
    # messages_thread.ajouter_consumer(q1)

    # Demarrer traitement messages
    await messages_thread.start_async()

    tasks = [
        asyncio.create_task(messages_thread.run_async()),
        asyncio.create_task(run_tests(messages_thread, stop_event)),
    ]

    # Execution de la loop avec toutes les tasks
    await asyncio.tasks.wait(tasks, return_when=asyncio.tasks.FIRST_COMPLETED)


async def run_tests(messages_thread, stop_event):
    producer = messages_thread.get_producer()

    # Demarrer test (attendre connexion prete)
    await messages_thread.attendre_pret()
    logger.info("produire messages")

    fingerprint = 'z2i3XjxKWdNBTe1yCT5GVbZsA3p6caLtJjkt5BbMPQW8sYqtDQu'
    # fingerprint = 'z2i3XjxEqcTWSj5xiuEfCX4DMDB31U8ZvtPNqDrmRiteGDnjC1u'

    requete = {}
    reponse = await producer.executer_requete(requete, 'certificat', action=fingerprint,
                                              exchange=Constantes.SECURITE_PUBLIC)
    enveloppe = reponse.certificat
    logger.info("Reponse recue : %s", enveloppe)
    if enveloppe.fingerprint == fingerprint:
        logger.debug("Certificat correspond, meme fingerprint %s" % fingerprint)
    else:
        raise Exception("Mauvais certificat")

    stop_event.set()

    logger.info("Fin main()")


async def callback_reply_q(message, messages_module):
    logger.info("Message recu : %s" % message)
    # wait_event.wait(0.7)


async def callback_q_1(message, messages_module):
    logger.info("callback_q_1 Message recu : %s" % message)


async def callback_q_2(message, messages_module):
    logger.info("callback_q_2 Message recu : %s" % message)


if __name__ == '__main__':
    # logging.basicConfig()
    logging.basicConfig(format=LOGGING_FORMAT, level=logging.WARN)
    logging.getLogger(__name__).setLevel(logging.DEBUG)
    logging.getLogger('millegrilles').setLevel(logging.DEBUG)

    asyncio.run(main())
