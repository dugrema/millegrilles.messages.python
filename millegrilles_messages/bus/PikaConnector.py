import asyncio
import logging

from millegrilles_messages.bus.PikaBusConnection import MilleGrillesPikaBusConnection
from millegrilles_messages.bus.BusContext import MilleGrillesBusContext
from millegrilles_messages.bus.PikaChannel import MilleGrillesPikaChannel, ConnectionProvider
from millegrilles_messages.bus.PikaMessageProducer import MilleGrillesPikaMessageProducer
from millegrilles_messages.bus.PikaQueue import MilleGrillesPikaReplyQueueConsumer

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

        # Wire producer and reply Q
        self.__reply_queue = MilleGrillesPikaReplyQueueConsumer(context)
        self.__producer_channel = MilleGrillesPikaChannel(context)
        self.__producer_channel.setup(self)
        self.__producer_channel.add_queue(self.__reply_queue)

        self.__channels: list[MilleGrillesPikaChannel] = [self.__producer_channel]
        self.__producer = MilleGrillesPikaMessageProducer(context, self.__producer_channel, self.__reply_queue)

    @property
    def connection(self):
        return self._connection

    async def get_producer(self) -> MilleGrillesPikaMessageProducer:
        await self.__producer.ready()
        return self.__producer

    async def run(self):
        done, pending = await asyncio.wait([
            asyncio.create_task(self._connection.run()),
            asyncio.create_task(self.__channel_thread())
        ], return_when=asyncio.FIRST_COMPLETED)
        if self.__context.stopping is not True:
            self.__logger.exception("Thread quit unexpectedly: %s" % done)
            self.__context.stop()
        if len(pending) > 0:
            await asyncio.gather(*pending)

    async def __channel_thread(self):
        coros = [c.run() for c in self.__channels]
        await asyncio.gather(*coros)

    async def add_channel(self, channel: MilleGrillesPikaChannel):
        if self._connection.connected:
            raise Exception('Already running, cannot configure')
        self.__channels.append(channel)
        channel.setup(self)

    async def on_connect(self):
        self.__logger.debug("Bus connected, starting channels")
        for channel in self.__channels:
            await channel.start_consuming()

    async def on_disconnect(self):
        self.__logger.debug("Bus disconnected, closing channels")
        for channel in self.__channels:
            try:
                await channel.stop_consuming()
            except:
                self.__logger.exception("Error closing channel %s" % channel)
