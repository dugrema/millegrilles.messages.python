import asyncio
import json
import logging

from uuid import uuid4

from typing import Union, Optional, Callable, Awaitable

from millegrilles_messages.messages import Constantes
from millegrilles_messages.bus.BusContext import MilleGrillesBusContext
from millegrilles_messages.bus.PikaChannel import MilleGrillesPikaChannel
from millegrilles_messages.bus.PikaQueue import MilleGrillesPikaReplyQueueConsumer, MessageCorrelation
from millegrilles_messages.messages.EnveloppeCertificat import EnveloppeCertificat
from millegrilles_messages.messages.MessagesModule import MessagePending, MessageWrapper

from pika import BasicProperties

from millegrilles_messages.messages.ValidateurCertificats import CertificatInconnu


class MilleGrillesPikaMessageProducer:

    def __init__(self, context: MilleGrillesBusContext, channel: MilleGrillesPikaChannel, reply_queue: MilleGrillesPikaReplyQueueConsumer):
        self.__logger = logging.getLogger(__name__+'.'+self.__class__.__name__)
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
        if reply_to is True:
            properties.reply_to = self.__reply_queue.auto_name
        elif reply_to is not None:
            properties.reply_to = reply_to

        if correlation_id is not None:
            properties.correlation_id = correlation_id

        if headers:
            properties.headers = headers

        await self.__channel.publish(exchanges, routing_key, message.content, properties)

    async def send(self, message: Union[str, bytes], routing_key: str,
                   exchange: Optional[str] = None, correlation_id: str = None, reply_to: Union[bool, str] = None):
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

        exchanges = None
        if exchange is not None:
            exchanges = [exchange]

        pending = MessagePending(message, routing_key, exchanges, reply_to, correlation_id)
        await self.send_raw(pending)

    async def send_wait_reply(self, message: Union[str, bytes], routing_key: str,
                              exchange: Optional[str] = None, correlation_id: str = None,
                              reply_to: str = None, timeout=Constantes.CONST_WAIT_REPLY_DEFAULT,
                              domain: Optional[Union[str, list]] = None, role: Optional[str] = None):
        if reply_to is None:
            reply_to = self.__reply_queue.auto_name

        if correlation_id is None:
            correlation_id = str(uuid4())

        # Conserver reference a la correlation
        correlation_reponse = MessageCorrelation(correlation_id, timeout=timeout, domain=domain, role=role)

        try:
            async with self.__semaphore_correlations:
                self.__reply_queue.add_correlation(correlation_reponse)
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
            noformat=False, nowait=False, attachments: Optional[dict] = None, timeout=Constantes.CONST_WAIT_REPLY_DEFAULT,
            domain_check: Union[bool, str, list]=True, role_check: Optional[str] = None) -> Optional[MessageWrapper]:

        if noformat is True:
            message_id = message_in['id']
            message = message_in
        else:
            message, message_id = self.__context.formatteur.signer_message(
                kind, message_in, domain, action=action, partition=partition)

        if attachments is not None:
            message['attachements'] = attachments

        if correlation_id is None:
            # Add a message number to the message_id. If 2 identical messages are produced within the
            # same second (e.g. same content and estampille), the id is the same. The correlation is not
            # unique for this producer in that case.
            # Using: [message_counter]/[message.id] as correlation_id.
            correlation_id = '%d/%s' % (self.__message_counter, message_id)
            self.__message_counter += 1  # Increment message counter

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
            if domain_check is True:
                domain_verification = domain
            elif isinstance(domain_check, str):
                domain_verification = domain_check
            elif isinstance(domain_check, list):
                domain_verification = domain_check
            else:
                domain_verification = None

            response = await self.send_wait_reply(
                message_bytes, '.'.join(rk),
                exchange=exchange, correlation_id=correlation_id, reply_to=reply_to, timeout=timeout,
                domain=domain_verification, role=role_check)

        return response

    async def request(self, message_in: dict, domain: str, action: str, exchange: str, partition: Optional[str] = None,
            reply_to: Optional[str] = None, correlation_id: Optional[str] = None,
            noformat=False, attachments: Optional[dict] = None, nowait = False, timeout=Constantes.CONST_WAIT_REPLY_DEFAULT,
            role_check: Optional[str] = None, domain_check: Optional[Union[bool, str, list]] = None) -> Optional[MessageWrapper]:
        if domain_check is not False:
            domain_check = domain_check or role_check is None
        if nowait:
            reply_to = reply_to or True  # True will use the reply_q name
        return await self.send_routed_message(
            message_in, Constantes.KIND_REQUETE, domain, action, exchange, partition, reply_to, correlation_id,
            noformat, nowait, attachments, timeout, domain_check, role_check)

    async def command(self, message_in: dict, domain: str, action: str, exchange: str, partition: Optional[str] = None,
            reply_to: Optional[str] = None, correlation_id: Optional[str] = None,
            noformat=False, nowait=False, attachments: Optional[dict] = None, timeout=Constantes.CONST_WAIT_REPLY_DEFAULT,
            role_check: Optional[str] = None, domain_check: Optional[Union[bool, str, list]] = None) -> Optional[MessageWrapper]:
        if domain_check is not False:
            domain_check = domain_check or role_check is None
        if nowait:
            reply_to = reply_to or True  # True will use the reply_q name
        return await self.send_routed_message(
            message_in, Constantes.KIND_COMMANDE, domain, action, exchange, partition, reply_to, correlation_id,
            noformat, nowait, attachments, timeout, domain_check, role_check)

    async def event(self, message_in: dict, domain: str, action: str, exchange: str, partition: Optional[str] = None,
            reply_to: Optional[str] = None, correlation_id: Optional[str] = None,
            noformat=False, attachments: Optional[dict] = None, timeout=Constantes.CONST_WAIT_REPLY_DEFAULT):
        return await self.send_routed_message(
            message_in, Constantes.KIND_EVENEMENT, domain, action, exchange, partition, reply_to, correlation_id,
            noformat, True, attachments, timeout)

    async def reply(self, message_in: dict, reply_to: str, correlation_id: str, noformat=False, attachments: Optional[dict] = None):
        if noformat is True:
            message_id = message_in['id']
            message = message_id
        else:
            message, message_id = self.__context.formatteur.signer_message(Constantes.KIND_REPONSE, message_in)

        if attachments is not None:
            message['attachements'] = attachments

        message_bytes = json.dumps(message)
        return await self.send(message_bytes, routing_key=reply_to, correlation_id=correlation_id, reply_to=reply_to)

    async def encrypt_reply(self, keys: Union[EnveloppeCertificat, list[EnveloppeCertificat]], message_in: dict, reply_to: str, correlation_id: str,
                            attachments: Optional[dict] = None):

        if isinstance(keys, EnveloppeCertificat):
            keys = [keys]

        message, message_id = await self.__context.formatteur.chiffrer_message(keys, Constantes.KIND_REPONSE_CHIFFREE, message_in)

        if attachments is not None:
            message['attachements'] = attachments

        message_bytes = json.dumps(message)
        return await self.send(message_bytes, routing_key=reply_to, correlation_id=correlation_id, reply_to=reply_to)

    async def fetch_certificate(self, fingerprint: str):
        """ Charge un certificat a partir de son fingerprint """
        try:
            return await self.__context.verificateur_certificats.valider_fingerprint(fingerprint)
        except CertificatInconnu as ce:
            # Try to load from the bus
            try:
                cert_pems = await self.__context.verificateur_certificats.fetch_certificat(fingerprint, self)
                enveloppe = await self.__context.verificateur_certificats.valider(cert_pems)
                return enveloppe
            except asyncio.CancelledError as e:
                raise e
            except Exception as e:
                self.__logger.warning("Error trying to load certificate from bus: %s", e)
                pass

            # Failure to load the certificate. Raise original error
            raise ce

    async def add_streaming_correlation(self, correlation_id: str, callback: Callable[[str, MessageWrapper], Awaitable[None]], timeout=15,
                                        domain: Optional[Union[bool, str, list]] = None, role: Optional[Union[list, str]] = None):
        correlation_reponse = MessageCorrelation(correlation_id, callback=callback, timeout=timeout, domain=domain, role=role, stream=True)
        self.__reply_queue.add_correlation(correlation_reponse, run_thread=True)
