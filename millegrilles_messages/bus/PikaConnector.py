import asyncio
import logging

from asyncio import TaskGroup
from typing import Optional

from millegrilles_messages.bus.PikaBusConnection import MilleGrillesPikaBusConnection
from millegrilles_messages.bus.BusContext import MilleGrillesBusContext, ForceTerminateExecution
from millegrilles_messages.bus.PikaChannel import MilleGrillesPikaChannel, ConnectionProvider, \
    PikaChannelAlreadyConsumingException
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

        self.__stop_event = asyncio.Event()

        # Wire producer and reply Q
        self.__reply_queue = MilleGrillesPikaReplyQueueConsumer(context)
        self.__producer_channel = MilleGrillesPikaChannel(context)
        self.__producer_channel.setup(self)
        self.__producer_channel.add_queue(self.__reply_queue)

        self.__channels: list[MilleGrillesPikaChannel] = [self.__producer_channel]
        self.__producer = MilleGrillesPikaMessageProducer(context, self.__producer_channel, self.__reply_queue)
        self.__task_group: Optional[TaskGroup] = None

    @property
    def connection(self):
        return self._connection

    async def get_producer(self) -> MilleGrillesPikaMessageProducer:
        await self.__producer.ready()
        return self.__producer

    async def run(self):
        async with TaskGroup() as group:
            group.create_task(self._connection.run())
            group.create_task(self.__channel_thread())
            group.create_task(self.__stop_thread())

        # Ensure all channels shut down
        await self.__close_channels()

        if self.__context.stopping is not True:
            self.__logger.exception("MilleGrillesPikaConnector thread quit unexpectedly")
            self.__context.stop()
            raise ForceTerminateExecution()

        self.__logger.info("MilleGrillesPikaConnector.run thread closed")

    async def __stop_thread(self):
        await self.__context.wait()
        self.__stop_event.set()

    async def disconnect(self):
        self.__stop_event.set()

    async def __channel_thread(self):
        async with TaskGroup() as group:
            self.__task_group = group
            for c in self.__channels:
                group.create_task(c.run())
        self.__logger.info("MilleGrillesPikaConnector.__channel_thread thread closed")

    async def add_channel(self, channel: MilleGrillesPikaChannel):
        self.__channels.append(channel)
        if self._connection.connected:
            # Immediately start running the channel
            self.__task_group.create_task(channel.run())
        channel.setup(self)

    async def remove_channel(self, channel: MilleGrillesPikaChannel):
        try:
            await channel.close()
        except Exception as e:
            self.__logger.info("Error closing channel: %s" % e)
        self.__channels.remove(channel)

    async def on_connect(self):
        self.__logger.debug("Bus connected, starting channels")
        for channel in self.__channels:
            try:
                await channel.start_consuming()
            except PikaChannelAlreadyConsumingException:
                self.__logger.info("Channel already consuming during on_connect")

    async def __stop_consuming(self):
        for channel in self.__channels:
            try:
                await channel.stop_consuming()
            except:
                self.__logger.exception("Error stopping channel %s" % channel)

    async def __close_channels(self):
        for channel in self.__channels:
            try:
                await channel.close()
            except:
                self.__logger.exception("Error closing channel %s" % channel)

    async def on_disconnect(self):
        self.__logger.debug("Bus disconnected, closing channels")
        await self.__stop_consuming()
