import asyncio
import logging

from asyncio import Event as EventAsyncio
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
        # Loop thread tant que stop_event est clear. Note: thread est daemon, devrait fermer immediatement
        # meme si en attente asyncio.
        self.__messages_module.preparer_ressources()

        while not self.__stop_event.is_set():
            self.__logger.info("Debut thread asyncio MessagesThread")
            asyncio.run(self.__messages_module.run_async())

            # Attendre pour redemarrer execution module
            self.__logger.info("Fin thread asyncio MessagesThread, attendre 30 secondes pour redemarrer")
            self.__stop_event.wait(30)

        self.__logger.info("Fin thread MessagesThread")
