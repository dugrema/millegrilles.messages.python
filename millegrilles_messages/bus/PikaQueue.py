import asyncio
import datetime
import logging

from typing import Any, Callable, Optional, Coroutine, Union, Awaitable

from pika.channel import Channel
from pika.frame import Method
from pika.spec import Basic, BasicProperties

from millegrilles_messages.FileLocking import DEFAULT_TIMEOUT
from millegrilles_messages.bus.BusContext import MilleGrillesBusContext
from millegrilles_messages.messages.MessagesModule import MessageWrapper

CONST_WAIT_REPLY_DEFAULT = 15


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
        self._context = context
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

    @property
    def running(self):
        return self.__running

    async def start_consuming(self, channel: Channel):
        self.__channel = channel
        loop = asyncio.get_event_loop()
        event = asyncio.Event()
        def consume_callback(method: Method):
            loop.call_soon(event.set)
        self.__consumer_tag = channel.basic_consume(self.auto_name, self.__on_message, callback=consume_callback)
        await asyncio.wait_for(event.wait(), 3)

    async def stop_consuming(self):
        if self.__channel.is_open and self.__consumer_tag:
            self.__channel.basic_cancel(self.__consumer_tag)
        self.__consumer_tag = None
        await self.__async_queue.put(None)  # Makes the async run exit if appropriate

    def add_routing_key(self, routing_key: RoutingKey):
        if self.__running:
            raise Exception('Already running, cannot configure')
        self.routing_keys.append(routing_key)

    def __on_message(self, channel: Channel, deliver: Basic.Deliver, properties: BasicProperties, body: bytes):
        message = RawMessageWrapper(channel, deliver, properties, body)
        self.__async_queue.put_nowait(message)

    async def run(self):
        self.__running = True
        while self._context.stopping is False:
            message = await self.__async_queue.get()
            if message is None:
                break  # Done

            # Parse and verify message

            try:
                await self.__callback(message)
            except Exception as e:
                self.__logger.exception('**UNHANDLED ERROR**: %s' % e)
            finally:
                self.__channel.basic_ack(message.deliver.delivery_tag)


class CancelledException(Exception):
    pass


class MessageCorrelation:

    def __init__(self, correlation_id: str, timeout=DEFAULT_TIMEOUT, callback=Callable[[int, MessageWrapper], Awaitable[None]]):
        self.__logger = logging.getLogger(__name__+'.'+self.__class__.__name__)
        self.correlation_id = correlation_id
        self.__creation_date = datetime.datetime.now()
        self.__timeout = timeout
        self.__callback = callback

        self.__event_attente = asyncio.Event()
        self.__stream_queue: Optional[asyncio.Queue] = None
        self.__reponse: Optional[MessageWrapper] = None
        self.__reponse_consommee = False
        self.__cancelled = False

        # if stream:
        #     self.__stream_queue = asyncio.Queue(maxsize=2)

    async def wait(self, timeout=DEFAULT_TIMEOUT) -> MessageWrapper:
        self.__timeout = timeout
        await asyncio.wait_for(self.__event_attente.wait(), timeout)

        if self.__cancelled:
            raise CancelledException()

        self.__reponse_consommee = True
        return self.__reponse

    async def stream_reponse(self, timeout=DEFAULT_TIMEOUT):
        self.__timeout = timeout
        while self.__event_attente.is_set() is False:
            valeur = await asyncio.wait_for(self.__stream_queue.get(), timeout)
            if self.__cancelled:
                raise CancelledException()
            if valeur is None:
                break
            yield valeur

        self.__reponse_consommee = True

    async def recevoir_reponse(self, message: MessageWrapper):
        self.__reponse = message
        if self.__stream_queue is not None:
            # Verifier si on a l'attachement "streaming=True", indique que le stream n'est pas termine
            try:
                await self.__stream_queue.put(message)
                self.__creation_date = datetime.datetime.now()  # Reset expiration
                if message.parsed['__original']['attachements']['streaming'] is True:
                    pass  # Ok, continuer le streaming
            except (AttributeError, KeyError):
                # Streaming done
                self.__event_attente.set()
                await self.__stream_queue.put(message)
        elif self.__callback is not None:
            try:
                await self.__callback(self.correlation_id, message)
                self.__creation_date = datetime.datetime.now()  # Reset expiration
                if message.original['attachements']['streaming'] is True:
                    pass  # Ok, continuer le streaming
            except (AttributeError, KeyError, TypeError):
                # Streaming done
                self.__event_attente.set()
        else:
            self.__event_attente.set()

    def expired(self):
        duree_message = datetime.timedelta(seconds=self.__timeout)
        if self.__reponse_consommee:
            duree_message = duree_message * 3  # On donne un delai supplementaire si la reponse n'est pas consommee

        date_expiration = datetime.datetime.now() - duree_message

        return self.__creation_date < date_expiration

    async def cancel(self):
        if self.__reponse_consommee is False:
            self.__logger.debug("Correlation reponse %s annulee par le consumer" % self.correlation_id)
            self.__cancelled = True
            self.__event_attente.set()


class MilleGrillesPikaReplyQueueConsumer(MilleGrillesPikaQueueConsumer):

    def __init__(self, context: MilleGrillesBusContext, prefetch_count=1):
        self.__logger = logging.getLogger(__name__+'.'+self.__class__.__name__)
        super().__init__(context, self.__on_reply_message, exclusive=True, prefetch_count=prefetch_count)
        self.__correlations: dict[str, MessageCorrelation] = dict()

    async def run(self):
        done, pending = await asyncio.wait([
            asyncio.create_task(super().run()),
            asyncio.create_task(self.__thread_maintain_correlations()),
        ], return_when=asyncio.FIRST_COMPLETED)
        if self._context.stopping is not True:
            self.__logger.error("Thread quit unexpectedly: %s" % done)
            self._context.stop()
        if len(pending) > 0:
            await asyncio.gather(*pending)

    async def __thread_maintain_correlations(self):
        while self._context.stopping is False:
            # List expired correlation ids
            expired_ids = list()
            for c in self.__correlations.values():
                if c.expired():
                    expired_ids.append(c.correlation_id)
                    await c.cancel()

            for expired_id in expired_ids:
                try:
                    del self.__correlations[expired_id]
                except KeyError:
                    pass

            await self._context.wait(30)

    async def __on_reply_message(self, message: RawMessageWrapper):
        raise NotImplementedError('todo')

    def add_correlation(self, correlation: MessageCorrelation):
        self.__correlations[correlation.correlation_id] = correlation

    def remove_correlation(self, correlation_id: str):
        try:
            del self.__correlations[correlation_id]
        except KeyError:
            pass

    async def stop_consuming(self):
        await super().stop_consuming()

        # Cancel all threads waiting for replys
        for c in self.__correlations.values():
            await c.cancel()
