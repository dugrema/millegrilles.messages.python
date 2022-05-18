import logging
from threading import Event

from millegrilles.messages.MessagesThread import MessagesThread

logger = logging.getLogger(__name__)


def main():
    logger.info("Debut main()")
    stop_event = Event()
    messages_thread = MessagesThread(stop_event)
    messages_thread.start(callback_reply_q, True)

    logger.info("Attente")
    stop_event.wait(300)
    stop_event.set()

    logger.info("Fin main()")


def callback_reply_q(message):
    logger.info("Message recu : %s" % message)


if __name__ == '__main__':
    logging.basicConfig()
    logging.getLogger(__name__).setLevel(logging.DEBUG)
    logging.getLogger('millegrilles').setLevel(logging.DEBUG)
    main()
