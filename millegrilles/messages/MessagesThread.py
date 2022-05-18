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
        self.__stop_event_asyncio: Optional[EventAsyncio] = None
        self.__thread: Optional[Thread] = None

        self.__logger.info("Utilisation module messages %s" % module_class.__name__)
        self.__messages_module = module_class()

    def start(self):
        self.__thread = Thread(target=self.run, daemon=True)
        self.__thread.start()

    def run(self):
        self.__logger.info("Debut thread asyncio MessagesThread")
        asyncio.run(self.__asyncio_loop())
        self.__logger.info("Fin thread asyncio MessagesThread")

    async def entretien(self):
        self.__logger.debug("Debut cycle entretien")

        await self.__messages_module.entretien()

        self.__logger.debug("Fin cycle entretien")

    async def __asyncio_loop(self):
        self.__stop_event_asyncio = EventAsyncio()

        # Loop thread tant que stop_event est clear. Note: thread est daemon, devrait fermer immediatement
        # meme si en attente asyncio.
        while not self.__stop_event.is_set():

            await self.entretien()

            # Attendre pour entretien
            try:
                await asyncio.wait_for(self.__stop_event_asyncio.wait(), 30)
            except asyncio.exceptions.TimeoutError:
                pass

        self.__logger.info("Fin thread MessagesThread")
