import asyncio
import datetime
import logging
from asyncio import TaskGroup

from typing import Optional

from pika.channel import Channel
from pika.frame import Method
from pika.spec import BasicProperties, Basic

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
        if prefetch_count > 1:
            raise NotImplementedError('Prefect stuck at 1, need to work on threading for ACKs')
        self.__prefetch_count = prefetch_count

        self.__connector: Optional[ConnectionProvider] = None

        self.__channel: Optional[Channel] = None
        self.__queues: list[MilleGrillesPikaQueueConsumer] = list()

        self.__q_change_event = asyncio.Event()
        self.__running = False
        self.__task_group: Optional[TaskGroup] = None

        self.ready = asyncio.Event()
        self.__waiting_send: dict[int, dict] = dict()
        self.__publish_count = 1
        self.__last_delivery = 0

    def setup(self, connector: ConnectionProvider):
        self.__connector = connector

    def on_delivery_confirmation(self, frame: Method):
        delivery_tag = frame.method.delivery_tag
        last_delivery = self.__last_delivery
        self.__last_delivery = delivery_tag

        is_ok = isinstance(frame.method, Basic.Ack)

        for no in range(last_delivery+1, delivery_tag+1):
            try:
                item = self.__waiting_send[no]
            except KeyError:
                continue

            try:
                item['ok'] = is_ok
                loop = asyncio.get_event_loop()
                loop.call_soon(item['event'].set)
            except:
                self.__logger.exception("Error processing delivery tag")

    async def __stop_thread(self):
        await self.__context.wait()
        self.__q_change_event.set()

    async def run(self):
        self.__logger.info("Channel thread starting")
        self.__running = True
        async with TaskGroup() as group:
            group.create_task(self.__stop_thread())
            for q in self.__queues:
                group.create_task(q.run())

        self.__logger.info("Channel thread closed")

    def add_queue(self, queue: MilleGrillesPikaQueueConsumer):
        queue.setup(self.__prefetch_count)
        self.__queues.append(queue)
        if self.ready.is_set() is True:
            # Start running immediately
            self.__task_group.create_task(queue.run())

    def remove_queue(self, queue: MilleGrillesPikaQueueConsumer):
        queue.close()
        self.__queues.remove(queue)
        # self.__q_change_event.set()

    async def start_consuming(self):
        # Connect new channel
        self.__channel = await self.__connector.connection.open_channel()
        self.__publish_count = 1
        self.__channel.add_on_close_callback(self.on_close)
        self.__channel.confirm_delivery(ack_nack_callback=self.on_delivery_confirmation)
        await self.set_qos()
        try:
            for q in self.__queues:
                await self.create_q(q)
                await q.start_consuming(self.__channel)
        except AttributeError:
            self.__logger.info("Error in start_consuming, aborting")
            return
        self.ready.set()

    def on_close(self, channel: Channel, reason: str):
        self.__channel = None
        self.__logger.debug("Channel %s closing" % channel)
        if self.ready.is_set() is True:
            # This is an error, try to force shutdown
            self.__context.stop()
            loop = asyncio.get_event_loop()
            loop.call_soon(self.__q_change_event.set)

    async def stop_consuming(self):
        self.ready.clear()
        for q in self.__queues:
            try:
                await q.stop_consuming()
            except Exception as e:
                self.__logger.info("Error stop_consuming: %s" % e)
        if self.__channel:
            self.__channel.close()
        self.__channel = None
        self.__q_change_event.set()

    async def close(self):
        await self.stop_consuming()
        for q in self.__queues:
            await q.close()

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

    async def publish(self, exchanges: Optional[list], routing_key: str, content: bytes, properties: Optional[BasicProperties] = None):
        if exchanges is not None:
            for exchange in exchanges:
                await self.__publish(exchange, routing_key, content, properties)
        else:
            await self.__publish('', routing_key, content, properties)

    async def __publish(self, exchange: str, routing_key: str, content: bytes, properties: Optional[BasicProperties] = None):
        event = asyncio.Event()
        item_no = self.__publish_count
        self.__publish_count += 1
        wait_dict = {'event': event, 'created': datetime.datetime.now(), 'no': item_no}
        try:
            self.__waiting_send[item_no] = wait_dict
            self.__channel.basic_publish(exchange=exchange, routing_key=routing_key, body=content,
                                         properties=properties, mandatory=True)

            # Wait for send confirmation
            if len(content) > 1_000_000:  # Very large message, give ample time to transfer
                wait_time = 30
            elif len(content) > 256_000:  # Large message
                wait_time = 10
            else:
                wait_time = 5
            await asyncio.wait_for(event.wait(), wait_time)
        finally:
            # Cleanup
            del self.__waiting_send[item_no]

        if wait_dict.get('ok') is not True:
            raise Exception("NACK on send")
