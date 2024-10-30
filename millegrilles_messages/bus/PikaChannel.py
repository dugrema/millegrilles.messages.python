import asyncio
import datetime
import logging

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
        self.__prefetch_count = prefetch_count

        self.__connector: Optional[ConnectionProvider] = None

        self.__channel: Optional[Channel] = None
        self.__queues: list[MilleGrillesPikaQueueConsumer] = list()

        self.__q_change_event = asyncio.Event()
        self.__running = False

        self.ready = asyncio.Event()
        self.__waiting_send: dict[int, dict] = dict()
        self.__publish_count = 1

    def setup(self, connector: ConnectionProvider):
        self.__connector = connector

    def on_delivery_confirmation(self, frame: Method):
        delivery_tag = frame.method.delivery_tag
        try:
            item = self.__waiting_send[delivery_tag]
        except KeyError:
            return  # Mismatch

        if isinstance(frame.method, Basic.Ack):
            item['ok'] = True
        else:
            item['ok'] = False

        loop = asyncio.get_event_loop()
        loop.call_soon(item['event'].set)

    async def run(self):
        self.__q_change_event.clear()  # Avoids recycling watch thread
        tasks = [asyncio.create_task(self.__change_watcher_thread())]

        while len(tasks) > 0:
            for q in self.__queues:
                if q.running is False:
                    tasks.append(asyncio.create_task(q.run()))

            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            tasks = list(pending)

            if self.__context.stopping is False and self.__q_change_event.is_set() is True:
                # Put change watcher back in list
                self.__q_change_event.clear()
                tasks.append(asyncio.create_task(self.__change_watcher_thread()))
            else:
                if self.ready.is_set():
                    # Perform clean shutdown
                    await self.stop_consuming()

        self.__logger.info("Channel thread closed")

    async def __change_watcher_thread(self):
        await self.__q_change_event.wait()

    def add_queue(self, queue: MilleGrillesPikaQueueConsumer):
        queue.setup(self.__prefetch_count)
        self.__queues.append(queue)
        self.__q_change_event.set()

    def remove_queue(self, queue: MilleGrillesPikaQueueConsumer):
        queue.stop_consuming()
        self.__queues.remove(queue)
        self.__q_change_event.set()

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
            # Try to force shutdown
            loop = asyncio.get_event_loop()
            loop.call_soon(self.__q_change_event.set)

    async def stop_consuming(self):
        self.ready.clear()
        for q in self.__queues:
            await q.stop_consuming()
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
        wait_dict = {'event': event, 'created': datetime.datetime.now()}
        try:
            self.__waiting_send[item_no] = wait_dict
            self.__channel.basic_publish(exchange=exchange, routing_key=routing_key, body=content,
                                         properties=properties, mandatory=True)
            # Wait for send confirmation
            await asyncio.wait_for(event.wait(), 5)
        finally:
            # Cleanup
            del self.__waiting_send[item_no]

        if wait_dict.get('ok') is not True:
            raise Exception("NACK on send")
