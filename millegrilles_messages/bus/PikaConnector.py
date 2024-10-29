import asyncio
import logging

from typing import Optional

from millegrilles_messages.bus.PikaBusConnection import MilleGrillesPikaBusConnection
from millegrilles_messages.bus.BusContext import MilleGrillesBusContext
from millegrilles_messages.bus.PikaChannel import MilleGrillesPikaChannel, ConnectionProvider
from millegrilles_messages.bus.PikaQueue import MilleGrillesPikaQueueConsumer

CONST_CONNECTION_ATTEMTPS = 5
CONST_RETRY_DELAY = 5.0
CONST_HEARTBEAT = 30
CONST_BLOCKED_CONNECTION_TIMEOUT = 20


class MilleGrillesPikaConnector(ConnectionProvider):

    def __init__(self, context: MilleGrillesBusContext):
        super().__init__()
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__context = context
        self._connection = MilleGrillesPikaBusConnection(context, self.on_connect, self.on_disconnect)
        self.__channels: list[MilleGrillesPikaChannel] = list()

    @property
    def connection(self):
        return self._connection

    async def run(self):
        await asyncio.gather(
            self._connection.run(),
            self.__channel_thread()
        )

    async def __channel_thread(self):
        coros = [c.run() for c in self.__channels]
        await asyncio.gather(*coros)

    async def add_channel(self, channel: MilleGrillesPikaChannel):
        self.__channels.append(channel)
        channel.setup(self)
        if self._connection.connected:
            await channel.start_consuming()

    async def remove_channel(self, channel: MilleGrillesPikaChannel):
        self.__channels.remove(channel)
        await channel.stop_consuming()

    async def on_connect(self):
        self.__logger.debug("Bus connected, starting channels")
        for channel in self.__channels:
            await channel.start_consuming()

    async def on_disconnect(self):
        self.__logger.debug("Bus disconnected, closing channels")
        for channel in self.__channels:
            await channel.stop_consuming()
