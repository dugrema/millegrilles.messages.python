import asyncio

from millegrilles_messages.bus.BusContext import MilleGrillesBusContext
from millegrilles_messages.bus.PikaChannel import MilleGrillesPikaChannel
from millegrilles_messages.bus.PikaQueue import MilleGrillesPikaReplyQueueConsumer
from millegrilles_messages.messages.MessagesModule import MessagePending

from pika import BasicProperties


class MilleGrillesPikaMessageProducer:

    def __init__(self, context: MilleGrillesBusContext, channel: MilleGrillesPikaChannel, reply_queue: MilleGrillesPikaReplyQueueConsumer):
        self.__context: MilleGrillesBusContext = context
        self.__channel: MilleGrillesPikaChannel = channel
        self.__reply_queue: MilleGrillesPikaReplyQueueConsumer = reply_queue

    async def ready(self):
        if self.__channel.ready.is_set() is False:
            await asyncio.wait_for(self.__channel.ready.wait(), 5)
        return self.__channel.ready.is_set()

    async def send(self, message: MessagePending):
        if await self.ready() is False:
            raise Exception('Channel not ready')

        exchanges = message.exchanges
        routing_key = message.routing_key
        reply_to = message.reply_to
        correlation_id = message.correlation_id
        headers = message.headers

        delivery_mode_v = 1

        properties = BasicProperties(content_type='test/plain', delivery_mode=delivery_mode_v)
        if reply_to is not None:
            properties.reply_to = reply_to
        if correlation_id is not None:
            properties.correlation_id = correlation_id
        if headers:
            properties.headers = headers

        await self.__channel.publish(exchanges, routing_key, message.content, properties)
