import logging
from threading import Event
from pika.exchange_type import ExchangeType

from millegrilles.messages import Constantes
from millegrilles.messages.MessagesThread import MessagesThread
from millegrilles.messages.MessagesModule import RessourcesConsommation, ExchangeConfiguration

logger = logging.getLogger(__name__)

LOGGING_FORMAT = '%(asctime)s %(threadName)s %(levelname)s: %(message)s'


def main():
    logger.info("Debut main()")
    stop_event = Event()

    # Preparer resources consumer
    exchange_1 = ExchangeConfiguration("1.public", ExchangeType.topic)

    reply_res = RessourcesConsommation(callback_reply_q)
    q1 = RessourcesConsommation(callback_q_1, 'CoreBackup/tada')
    q1.ajouter_rk('3.protege', 'commande.CoreBackup.m1')
    q1.ajouter_rk('2.prive', 'commande.CoreBackup.m2')

    q2 = RessourcesConsommation(callback_q_2, 'CoreBackup/titi', durable=True)
    q2.set_ttl(30000)
    q2.ajouter_rk('2.prive', 'evenement.CoreBackup.t1')
    q2.ajouter_rk('2.prive', 'commande.CoreBackup.t2')

    messages_thread = MessagesThread(stop_event)
    # messages_thread.ajouter_exchange(exchange_1)
    messages_thread.set_reply_ressources(reply_res)
    messages_thread.ajouter_consumer(q1)
    messages_thread.ajouter_consumer(q2)

    # Demarrer traitement messages
    messages_thread.start()
    producer = messages_thread.get_producer()

    # Demarrer test (attendre connexion prete)
    messages_thread.attendre_pret()
    logger.info("produire messages")

    reply_q = producer.get_reply_q()
    for i in range(0, 1000):
        # message = 'message %d' % i
        # producer.emettre(message, reply_q)
        evenement = {"value": i, "texte": "Allo"}
        producer.emettre_evenement(evenement, domaine='CoreBackup', action='t1', exchanges=[Constantes.SECURITE_PRIVE])
        # stop_event.wait(0.001)

    logger.info("Attente")
    stop_event.wait(300)
    stop_event.set()

    logger.info("Fin main()")


wait_event = Event()


def callback_reply_q(message):
    logger.info("Message recu : %s" % message)
    # wait_event.wait(0.7)


def callback_q_1(message):
    logger.info("callback_q_1 Message recu : %s" % message)


def callback_q_2(message):
    logger.info("callback_q_2 Message recu : %s" % message)


if __name__ == '__main__':
    # logging.basicConfig()
    logging.basicConfig(format=LOGGING_FORMAT, level=logging.WARN)
    logging.getLogger(__name__).setLevel(logging.DEBUG)
    logging.getLogger('millegrilles').setLevel(logging.DEBUG)
    main()
