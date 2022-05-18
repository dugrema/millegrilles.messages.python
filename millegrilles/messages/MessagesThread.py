import logging

from threading import Thread, Event
from typing import Optional

from millegrilles.messages.MessagesModule import MessagesModule
from millegrilles.pika.PikaModule import PikaModule


class MessagesThread:

    def __init__(self, stop_event: Event, module_class: MessagesModule = PikaModule):
        print("Logger %s.%s" % (__name__, self.__class__.__name__))
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__stop_event = stop_event
        self.__thread: Optional[Thread] = None

        self.__logger.info("Utilisation module messages %s" % module_class.__name__)
        self.__messages_module = module_class()

    def start(self):
        self.__thread = Thread(target=self.run, daemon=True)
        self.__thread.start()

    def run(self):
        self.__logger.info("Debut thread MessagesThread")
        while not self.__stop_event.is_set():

            self.entretien()

            # Attendre pour entretien
            self.__stop_event.wait(15)

        self.__logger.info("Fin thread MessagesThread")

    def entretien(self):
        self.__logger.debug("Debut cycle entretien")

        self.__logger.debug("Fin cycle entretien")

