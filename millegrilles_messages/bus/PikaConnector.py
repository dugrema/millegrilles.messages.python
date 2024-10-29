import asyncio
import logging
import pika
import ssl

from typing import Optional

from pika.adapters.asyncio_connection import AsyncioConnection
from pika.exchange_type import ExchangeType

from millegrilles_messages.bus.PikaBusConnection import MilleGrillesPikaBusConnection
from millegrilles_messages.messages.EnveloppeCertificat import EnveloppeCertificat
from millegrilles_messages.bus.BusContext import MilleGrillesBusContext

CONST_CONNECTION_ATTEMTPS = 5
CONST_RETRY_DELAY = 5.0
CONST_HEARTBEAT = 30
CONST_BLOCKED_CONNECTION_TIMEOUT = 20


class MilleGrillesPikaConnector:

    EXCHANGE = 'message'
    EXCHANGE_TYPE = ExchangeType.topic
    QUEUE = 'text'
    ROUTING_KEY = 'example.text'

    def __init__(self, context: MilleGrillesBusContext):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__context = context
        self._connection = MilleGrillesPikaBusConnection(context)

    async def run(self):
        await asyncio.gather(
            self._connection.run(),
            self.maintenance_thread(),
        )

    async def maintenance_thread(self):
        while self.__context.stopping is False:
            await self.__context.wait(duration=30)

