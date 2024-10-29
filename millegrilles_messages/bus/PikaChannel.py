import asyncio
import logging

from typing import Optional

from pika.channel import Channel
from pika.frame import Method

from millegrilles_messages.bus.BusContext import MilleGrillesBusContext
from millegrilles_messages.bus.PikaBusConnection import MilleGrillesPikaBusConnection
from millegrilles_messages.bus.PikaQueue import MilleGrillesPikaQueueConsumer, RoutingKey


class ConnectionProvider:

    def __init__(self):
        pass

    @property
    def connection(self) -> MilleGrillesPikaBusConnection:
        raise NotImplementedError()


class MilleGrillesPikaChannel:

    def __init__(self, context: MilleGrillesBusContext, prefetch_count=1):
        self.__logger = logging.getLogger(__name__+'.'+self.__class__.__name__)
        self.__context = context
        self.__prefetch_count = prefetch_count

        self.__connector: Optional[ConnectionProvider] = None

        self.__channel: Optional[Channel] = None
        self.__queues: list[MilleGrillesPikaQueueConsumer] = list()

    def setup(self, connector: ConnectionProvider):
        self.__connector = connector

    async def run(self):
        coros = [q.run() for q in self.__queues]
        await asyncio.gather(*coros)

    def add_queue(self, queue: MilleGrillesPikaQueueConsumer):
        self.__queues.append(queue)

    def remove_queue(self, queue: MilleGrillesPikaQueueConsumer):
        queue.stop_consuming()
        self.__queues.remove(queue)

    async def start_consuming(self):
        # Connect new channel
        self.__channel = await self.__connector.connection.open_channel()
        self.__channel.add_on_close_callback(self.on_close)
        await self.set_qos()
        for q in self.__queues:
            await self.create_q(q)
            await q.start_consuming(self.__channel)

    def on_close(self, channel: Channel, reason: str):
        self.__channel = None
        self.__logger.debug("Channel %s closing" % channel)

    async def stop_consuming(self):
        for q in self.__queues:
            await q.stop_consuming()
        if self.__channel:
            self.__channel.close()
        self.__channel = None

    async def set_qos(self):
        loop = asyncio.get_event_loop()
        event = asyncio.Event()
        def qos_callback(method: Method):
            loop.call_soon(event.set)
        self.__channel.basic_qos(prefetch_count=self.__prefetch_count, callback=qos_callback)
        await asyncio.wait_for(event.wait(), 3)

    async def create_q(self, q: MilleGrillesPikaQueueConsumer):
        loop = asyncio.get_event_loop()
        event = asyncio.Event()
        name = q.name or ''
        def queue_declare_callback(frame: Method):
            q.auto_name = frame.method.queue
            loop.call_soon(event.set)
        self.__channel.queue_declare(name, durable=q.durable, exclusive=q.exclusive,
                                     auto_delete=q.auto_delete, arguments=q.arguments,
                                     callback=queue_declare_callback)
        await asyncio.wait_for(event.wait(), 5)

        for rk in q.routing_keys:
            await self.bind_routing_key(q, rk)

    async def bind_routing_key(self, q: MilleGrillesPikaQueueConsumer, rk: RoutingKey):
        name = q.auto_name

        loop = asyncio.get_event_loop()
        event = asyncio.Event()
        def bind_callback(method: Method):
            loop.call_soon(event.set)

        self.__channel.queue_bind(name, rk.exchange, rk.routing_key, callback=bind_callback)
        await asyncio.wait_for(event.wait(), 5)
