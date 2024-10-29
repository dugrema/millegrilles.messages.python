import asyncio
import json

from uuid import uuid4

from typing import Union, Optional

from millegrilles_messages.messages import Constantes
from millegrilles_messages.bus.BusContext import MilleGrillesBusContext
from millegrilles_messages.bus.PikaChannel import MilleGrillesPikaChannel
from millegrilles_messages.bus.PikaQueue import MilleGrillesPikaReplyQueueConsumer, MessageCorrelation, \
    CancelledException
from millegrilles_messages.messages.MessagesModule import MessagePending, MessageWrapper

from pika import BasicProperties

CONST_WAIT_REPLY_DEFAULT = 15


class MilleGrillesPikaMessageProducer:

    def __init__(self, context: MilleGrillesBusContext, channel: MilleGrillesPikaChannel, reply_queue: MilleGrillesPikaReplyQueueConsumer):
        self.__context: MilleGrillesBusContext = context
        self.__channel: MilleGrillesPikaChannel = channel
        self.__reply_queue: MilleGrillesPikaReplyQueueConsumer = reply_queue
        self.__message_counter = 0
        self.__semaphore_correlations = asyncio.BoundedSemaphore(value=100)  # Max requests waiting at the same time

    async def ready(self):
        if self.__channel.ready.is_set() is False:
            await asyncio.wait_for(self.__channel.ready.wait(), 5)
        return self.__channel.ready.is_set()

    async def send_raw(self, message: MessagePending):
        if await self.ready() is False:
            raise Exception('Channel not ready')

        exchanges = message.exchanges
        routing_key = message.routing_key
        reply_to = message.reply_to
        correlation_id = message.correlation_id
        headers = message.headers

        delivery_mode_v = 1

        properties = BasicProperties(content_type=message.content_type, delivery_mode=delivery_mode_v)
        if reply_to is not None:
            properties.reply_to = reply_to
        if correlation_id is not None:
            properties.correlation_id = correlation_id
        if headers:
            properties.headers = headers

        await self.__channel.publish(exchanges, routing_key, message.content, properties)

    async def send(self, message: Union[str, bytes], routing_key: str,
                   exchange: Optional[str] = None, correlation_id: str = None, reply_to: str = None):
        """
        Send message without waiting. Can be used to redirect reply to other system.
        :param message:
        :param routing_key:
        :param exchange:
        :param correlation_id:
        :param reply_to:
        :return:
        """

        if isinstance(message, str):
            message = message.encode('utf-8')

        pending = MessagePending(message, routing_key, [exchange], reply_to, correlation_id)
        await self.send_raw(pending)

    async def send_wait_reply(self, message: Union[str, bytes], routing_key: str,
                              exchange: Optional[str] = None, correlation_id: str = None,
                              reply_to: str = None, timeout=CONST_WAIT_REPLY_DEFAULT):
        if reply_to is None:
            reply_to = self.__reply_queue.auto_name

        # Bug - si un message avec meme contenu est emis plusieurs fois durant la meme seconde,
        #       la correlation echoue (reponses des duplications sont perdues).
        #       Ajouter le compteur de messages pour rendre unique pour ce producer.
        if correlation_id is None:
            # correlation_id = str(uuid4())
            correlation_id = '%d_%s' % (self.__message_counter, str(uuid4()))
        else:
            correlation_id = '%d_%s' % (self.__message_counter, correlation_id)

        self.__message_counter += 1  # Incrementer compteur

        # Conserver reference a la correlation
        correlation_reponse = MessageCorrelation(correlation_id)

        async with self.__semaphore_correlations:
            self.__reply_queue.add_correlation(correlation_reponse)

            try:
                # Emettre le message
                await self.send(message, routing_key, exchange, correlation_id, reply_to)

                # Attendre la reponse. raises TimeoutError
                response = await correlation_reponse.wait(timeout)
            finally:
                self.__reply_queue.remove_correlation(correlation_reponse.correlation_id)

        return response

    async def send_routed_message(
            self, message_in: dict, kind: int, domain: str, action: str, exchange: str, partition: Optional[str] = None,
            reply_to: Optional[str] = None, correlation_id: Optional[str] = None,
            noformat=False, nowait=False, attachments: Optional[dict] = None, timeout=CONST_WAIT_REPLY_DEFAULT) -> [MessageWrapper, None]:

        if noformat is True:
            message_id = message_in['id']
            message = message_id
        else:
            message, message_id = self.__context.formatteur.signer_message(
                kind, message_in, domain, action=action, partition=partition)

        if attachments is not None:
            message['attachements'] = attachments

        correlation_id = correlation_id or str(message_id)

        if kind == Constantes.KIND_REQUETE:
            route_prefix = 'requete'
        elif kind == Constantes.KIND_COMMANDE:
            route_prefix = 'commande'
        elif kind == Constantes.KIND_EVENEMENT:
            route_prefix = 'evenement'
        elif kind == Constantes.KIND_COMMANDE_INTER_MILLEGRILLE:
            route_prefix = 'commande'
        else:
            raise Exception("Not a routable kind")

        rk = [route_prefix, domain]
        if partition is not None:
            rk.append(partition)
        rk.append(action)

        message_bytes = json.dumps(message)

        if nowait is True:
            await self.send(
                message_bytes, '.'.join(rk),
                exchange=exchange, correlation_id=correlation_id, reply_to=reply_to)
            response = None
        else:
            response = await self.send_wait_reply(
                message_bytes, '.'.join(rk),
                exchange=exchange, correlation_id=correlation_id, reply_to=reply_to, timeout=timeout)

        return response
