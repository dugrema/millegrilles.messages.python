import logging
from threading import Event

from millegrilles.messages.MessagesThread import MessagesThread, RessourcesConsommation

logger = logging.getLogger(__name__)

LOGGING_FORMAT = '%(asctime)s %(threadName)s %(levelname)s: %(message)s'


def main():
    logger.info("Debut main()")
    stop_event = Event()

    # Preparer resources consumer
    reply_res = RessourcesConsommation(callback_reply_q)

    messages_thread = MessagesThread(stop_event)
    messages_thread.set_reply_ressources(reply_res)

    # Demarrer traitement messages
    messages_thread.start()
    producer = messages_thread.get_producer()

    # Demarrer test (attendre connexion prete)
    messages_thread.attendre_pret()
    logger.info("produire messages")

    reply_q = producer.get_reply_q()
    for i in range(0, 10000):
        message = 'message %d' % i
        producer.emettre(message, reply_q)
        stop_event.wait(0.001)

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
