import asyncio
import logging

# from threading import Thread, Event
from asyncio import Event
from typing import Optional

from millegrilles_messages.messages.MessagesModule import MessagesModule, RessourcesConsommation, ExchangeConfiguration
from millegrilles_messages.pika.PikaModule import PikaModule


class MessagesThread:

    def __init__(self, stop_event: Event, module_class: MessagesModule = PikaModule):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__stop_event = stop_event
        # self.__thread: Optional[Thread] = None
        self.__event_loop = None

        self.__logger.info("Utilisation module messages %s" % module_class.__name__)
        self.__messages_module: MessagesModule = module_class()

        self.__env_configuration: Optional[dict] = None
        self.__reply_ressources: Optional[RessourcesConsommation] = None
        self.__consumer_ressources = list()
        self.__exchanges: Optional[list] = None

        self.__locked = False

    # def start(self):
    #     if self.__thread is not None:
    #         raise Exception("Deja demarre")
    #
    #     await self.__messages_module.preparer_ressources(
    #         self.__env_configuration, self.__reply_ressources, self.__consumer_ressources, self.__exchanges)
    #
    #     self.__thread = Thread(target=self.__run, daemon=True, name="asyncio_loop1")
    #     self.__thread.start()

    async def start_async(self):
        self.__event_loop = asyncio.get_event_loop
        if self.__locked is True:
            raise Exception("Deja demarre")

        await self.__messages_module.preparer_ressources(
            self.__env_configuration, self.__reply_ressources, self.__consumer_ressources, self.__exchanges)

        self.__locked = True

    async def run_async(self):
        # Loop thread tant que stop_event est clear. Note: thread est daemon, devrait fermer immediatement
        # meme si en attente asyncio.
        try:
            await self.__messages_module.run_async()
        finally:
            await self.__messages_module.fermer()

        # while not self.__stop_event.is_set():
        #     self.__logger.info("Debut thread asyncio MessagesThread")
        #
        #     # Run loop asyncio
        #     # asyncio.run(self.__messages_module.run_async())
        #     await self.__messages_module.run_async()
        #
        #     # Attendre pour redemarrer execution module
        #     self.__logger.info("Fin thread asyncio MessagesThread, attendre 30 secondes pour redemarrer")
        #     try:
        #         await asyncio.wait_for(self.__stop_event.wait(), 30)
        #     except TimeoutError:
        #         pass

        self.__logger.info("Fin thread MessagesThread")

    def get_producer(self):
        return self.__messages_module.get_producer()

    def set_env_configuration(self, env_configuration: dict):
        self.__env_configuration = env_configuration

    def set_reply_ressources(self, res: RessourcesConsommation):
        if self.__locked:
            raise Exception("Thread active, locked")

        self.__reply_ressources = res

    def ajouter_consumer(self, res: RessourcesConsommation):
        if self.__locked:
            raise Exception("Thread active, locked")

        self.__consumer_ressources.append(res)

    def ajouter_exchange(self, exchange: ExchangeConfiguration):
        if self.__exchanges is None:
            self.__exchanges = list()
        self.__exchanges.append(exchange)

    async def attendre_pret(self, max_delai=20):
        await self.__messages_module.attendre_pret(max_delai)

    def get_validateur_messages(self):
        return self.__messages_module.get_validateur_messages()

    def get_validateur_certificats(self):
        return self.__messages_module.get_validateur_certificats()
