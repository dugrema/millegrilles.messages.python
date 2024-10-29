import asyncio
import logging

from typing import Any, Callable, Optional, Coroutine, Union

from pika.channel import Channel
from pika.frame import Method
from pika.spec import Basic, BasicProperties

from millegrilles_messages.bus.BusContext import MilleGrillesBusContext


class RoutingKey:

    def __init__(self, exchange: str, routing_key: str):
        self.exchange = exchange
        self.routing_key = routing_key

    def __str__(self):
        return 'RoutingKey %s/%s' % (self.exchange, self.routing_key)

    def __hash__(self):
        return hash('.'.join([self.exchange, self.routing_key]))

    def __eq__(self, other):
        return other.exchange == self.exchange and other.routing_key == self.routing_key


class RawMessageWrapper:

    def __init__(self, channel: Channel, deliver: Basic.Deliver, properties: BasicProperties, body: bytes):
        self.channel = channel
        self.deliver = deliver
        self.properties = properties
        self.body = body


class MilleGrillesPikaQueueConsumer:

    def __init__(self, context: MilleGrillesBusContext, callback: Callable[[RawMessageWrapper], Coroutine[Any, Any, None]],
                 name: Optional[str] = None, exclusive=False, durable=False, auto_delete=False, arguments: Optional[dict] = None,
                 prefetch_count=1):
        self.__logger = logging.getLogger(__name__+'.'+self.__class__.__name__)
        self.__context = context
        self.__callback = callback

        # Queue configuration
        self.name = name  # If None, this is an auto-named Q and name will be saved in auto_name
        if name is None:
            self.exclusive = True
        else:
            self.exclusive = exclusive
        self.durable = durable
        self.auto_delete = auto_delete
        self.arguments = arguments

        self.routing_keys: list[RoutingKey] = list()

        self.__async_queue: asyncio.Queue[Union[RawMessageWrapper, None]] = asyncio.Queue(maxsize=prefetch_count)
        self.__running = False

        # Dynamic values
        self.auto_name: Optional[str] = None
        self.__channel: Optional[Channel] = None
        self.__consumer_tag: Optional[str] = None

        # self.actif = actif
        # self.nb_max_attente = 10

    @property
    def running(self):
        return self.__running

    async def start_consuming(self, channel: Channel):
        self.__channel = channel
        loop = asyncio.get_event_loop()
        event = asyncio.Event()
        def consume_callback(method: Method):
            loop.call_soon(event.set)
        self.__consumer_tag = channel.basic_consume(self.auto_name, self.on_message, callback=consume_callback)
        await asyncio.wait_for(event.wait(), 3)

    async def stop_consuming(self):
        if self.__channel.is_open:
            self.__channel.basic_cancel(self.__consumer_tag)
        self.__consumer_tag = None
        await self.__async_queue.put(None)  # Makes the async run exit if appropriate

    def add_routing_key(self, routing_key: RoutingKey):
        if self.__running:
            raise Exception('Already running, cannot configure')
        self.routing_keys.append(routing_key)

    def on_message(self, channel: Channel, deliver: Basic.Deliver, properties: BasicProperties, body: bytes):
        message = RawMessageWrapper(channel, deliver, properties, body)
        self.__async_queue.put_nowait(message)

    async def run(self):
        self.__running = True
        while self.__context.stopping is False:
            message = await self.__async_queue.get()
            if message is None:
                break  # Done
            try:
                await self.__callback(message)
            except Exception as e:
                self.__logger.exception('UNHANDLED ERROR: %s' % e)
            finally:
                self.__channel.basic_ack(message.deliver.delivery_tag)
