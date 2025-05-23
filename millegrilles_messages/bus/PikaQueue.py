import asyncio
import datetime
import logging
import json
from asyncio import TaskGroup

from typing import Any, Callable, Optional, Coroutine, Union, Awaitable

from cryptography.x509 import ExtensionNotFound
from pika.channel import Channel
from pika.frame import Method
from pika.spec import Basic, BasicProperties
from certvalidator.errors import PathValidationError
from cryptography.exceptions import InvalidSignature

from millegrilles_messages.chiffrage.DechiffrageUtils import dechiffrer_reponse
from millegrilles_messages.messages import Constantes
from millegrilles_messages.bus.BusContext import MilleGrillesBusContext
from millegrilles_messages.messages.Hachage import ErreurHachage
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

    def __init__(self, queue: str, channel: Channel, deliver: Basic.Deliver, properties: BasicProperties, body: bytes):
        self.queue = queue
        self.channel = channel
        self.deliver = deliver
        self.properties = properties
        self.body = body

    def to_message_wrapper(self) -> MessageWrapper:
        properties = self.properties
        basic_deliver = self.deliver
        correlation_id = properties.correlation_id
        reply_to = properties.reply_to
        exchange = basic_deliver.exchange
        routing_key = basic_deliver.routing_key
        delivery_tag = basic_deliver.delivery_tag

        return MessageWrapper(self.body, routing_key, self.queue, exchange, reply_to, correlation_id, delivery_tag)


class MilleGrillesPikaQueueConsumer:

    def __init__(self, context: MilleGrillesBusContext, callback: Callable[[MessageWrapper], Coroutine[Any, Any, Optional[dict]]],
                 name: Optional[str] = None, exclusive=False, durable=False, auto_delete=False,
                 arguments: Optional[dict] = None, allow_user_messages=False):
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
        self.allow_user_messages = allow_user_messages

        self.routing_keys: list[RoutingKey] = list()

        self.__async_queue: Optional[asyncio.Queue[Union[RawMessageWrapper, None]]] = None
        self.__running = False

        # Dynamic values
        self.auto_name: Optional[str] = None
        self.__channel: Optional[Channel] = None
        self.__consumer_tag: Optional[str] = None

        self.__loop = asyncio.get_event_loop()

    def setup(self, prefetch_count: int):
        self.__async_queue: asyncio.Queue[Union[RawMessageWrapper, None]] = asyncio.Queue(maxsize=prefetch_count)

    @property
    def running(self):
        return self.__running

    async def bind_routing_key(self, rk: RoutingKey, channel: Optional[Channel] = None):
        name = self.auto_name

        event = asyncio.Event()
        def bind_callback(method: Method):
            self.__loop.call_soon_threadsafe(event.set)
        channel = channel or self.__channel
        channel.queue_bind(name, rk.exchange, rk.routing_key, callback=bind_callback)
        await asyncio.wait_for(event.wait(), 5)

    async def start_consuming(self, channel: Channel):
        if self.__async_queue is None:
            raise Exception('Not initialized (setup)')

        self.__channel = channel
        event = asyncio.Event()
        def consume_callback(method: Method):
            self.__loop.call_soon_threadsafe(event.set)
        self.__consumer_tag = channel.basic_consume(self.auto_name, self.__on_message, auto_ack=False, callback=consume_callback)
        await asyncio.wait_for(event.wait(), 3)

    async def stop_consuming(self):
        if self.__channel.is_open and self.__consumer_tag:
            self.__channel.basic_cancel(self.__consumer_tag)
        self.__consumer_tag = None

    async def close(self):
        try:
            await self.stop_consuming()
        except Exception as e:
            self.__logger.info("Error stop consuming: %s" % e)
        await self.__async_queue.put(None)  # Makes the async run exit if appropriate

    def add_routing_key(self, routing_key: RoutingKey):
        if self.__running:
            raise Exception('Already running, use add_bind_routing_key')
        self.routing_keys.append(routing_key)

    async def add_bind_routing_key(self, routing_key: RoutingKey):
        self.routing_keys.append(routing_key)
        await self.bind_routing_key(routing_key)

    async def remove_unbind_routing_key(self, routing_key: RoutingKey):
        try:
            self.routing_keys.remove(routing_key)
        except ValueError:
            pass
        name = self.auto_name
        self.__channel.queue_unbind(name, routing_key.exchange, routing_key.routing_key)

    def remove_routing_key(self, routing_key: RoutingKey):
        if self.__running:
            raise Exception('Already running, cannot configure')
        try:
            self.routing_keys.remove(routing_key)
        except ValueError:
            pass  # Already removed

    def __on_message(self, channel: Channel, deliver: Basic.Deliver, properties: BasicProperties, body: bytes):
        message = RawMessageWrapper(self.auto_name or self.name, channel, deliver, properties, body)
        # self.__async_queue.put_nowait(message)
        # Note - put_nowait is safe because we use the same maxvalue as the queue prefetch count
        self.__loop.call_soon_threadsafe(self.__async_queue.put_nowait, message)

    async def run(self):
        if self.auto_name is None:
            if self.name is not None:
                self.auto_name = self.name
            else:
                raise Exception('queue not initialized')

        async with TaskGroup() as group:
            group.create_task(self.__run_consume())

    async def __run_consume(self):
        self.__running = True
        while self._context.stopping is False:
            message = await self.__async_queue.get()

            if message is None:
                break  # Exit condition

            try:
                # Parse and verify message
                message_wrapper = message.to_message_wrapper()
                message_dict: dict = json.loads(message.body.decode('utf-8'))
                message_wrapper.parsed = message_dict
                validateur = self._context.validateur_message
                enveloppe = await validateur.verifier(message_dict)
                message_wrapper.certificat = enveloppe
                message_wrapper.est_valide = True

                # Check the message domain/role
                try:
                    rk_split = message_wrapper.routing_key.split('.')
                    if message_wrapper.reply_to == message_wrapper.routing_key or rk_split[0] == 'amq':
                        domain_role = True  # This is a reply, it will be checked with the correlation
                    elif rk_split[0] in ('commande', 'requete'):
                        domain_role = True  # Messages from anyone can come in as requests or commands
                    else:
                        domain_role = rk_split[1]
                except (AttributeError, IndexError):
                    if message_wrapper.correlation_id is not None:
                        pass  # Likely a reply, will be checked at correlation
                    else:
                        self.__logger.info("MESSAGE DROPPED: No routing key domain nor correlation on %s" % message_wrapper.routing_key)
                        message_wrapper = None
                else:
                    domain_roles = set()
                    try:
                        domain_roles.update(enveloppe.get_roles)
                    except ExtensionNotFound:
                        pass
                    try:
                        domain_roles.update(enveloppe.get_domaines)
                    except ExtensionNotFound:
                        pass

                    if domain_role is True:
                        pass
                    elif domain_role in domain_roles:
                        pass
                    elif self.allow_user_messages and 'usager' in enveloppe.get_roles:
                        pass  # This is a user message - needs to be checked at the business logic level
                    else:
                        self.__logger.info("MESSAGE DROPPED: Routing key and certificate domain/role mismatch on %s" % message_wrapper.routing_key)
                        message_wrapper = None

            except json.JSONDecodeError:
                self.__logger.info("MESSAGE DROPPED: Invalid JSON message")
                message_wrapper = None
            except KeyError:
                self.__logger.info("MESSAGE DROPPED: Invalid parsed JSON message")
                message_wrapper = None
            except PathValidationError:
                self.__logger.info("MESSAGE DROPPED: Invalid certificate")
                message_wrapper = None
            except (ErreurHachage, InvalidSignature):
                self.__logger.info("MESSAGE DROPPED: Invalid message id (digest) or signature")
                message_wrapper = None
            except:
                self.__logger.exception("MESSAGE DROPPED: Error processing message")
                message_wrapper = None

            if message_wrapper and message_wrapper.kind in [6, 8]:
                original = message_wrapper.original
                try:
                    decrypted_content = dechiffrer_reponse(self._context.signing_key, original)
                    message_wrapper.set_parsed_dechiffre(decrypted_content)
                except KeyError:
                    # Unable to decrypt message - it me not be intended for this instance (e.g. web relay)
                    pass

            try:
                if message_wrapper and message_wrapper.est_valide:
                    response = await self.__callback(message_wrapper)
                    if response is not None:
                        # This is a reply
                        await self.respond(message_wrapper, response)
            except Exception as e:
                self.__logger.exception('**UNHANDLED ERROR**: %s' % e)
            finally:
                # ACK must be sent back on same channel as received
                message.channel.basic_ack(message.deliver.delivery_tag)


    async def respond(self, message_wrapper: MessageWrapper, response: dict):
        reply_to = message_wrapper.reply_to
        correlation_id = message_wrapper.correlation_id

        if reply_to and correlation_id:
            signed_response, response_id = self._context.formatteur.signer_message(Constantes.KIND_REPONSE, response)
            delivery_mode_v = 1
            properties = BasicProperties(content_type='application/json', delivery_mode=delivery_mode_v)
            # properties.reply_to = reply_to
            properties.correlation_id = correlation_id

            content = json.dumps(signed_response).encode('utf-8')
            self.__channel.basic_publish(exchange='', routing_key=reply_to, body=content, properties=properties)
        else:
            self.__logger.info("Cannot reply to message without correlation_id/reply_to: %s" % message_wrapper.routing_key)

        pass

class CancelledException(Exception):
    pass


class MessageCorrelation:

    def __init__(self, correlation_id: str, timeout=CONST_WAIT_REPLY_DEFAULT,
                 callback: Optional[Callable[[str, MessageWrapper], Awaitable[None]]] = None,
                 domain: Optional[Union[bool, str, list]] = None, role: Optional[Union[list, str]] = None,
                 stream=False):
        self.__logger = logging.getLogger(__name__+'.'+self.__class__.__name__)
        self.correlation_id = correlation_id
        self.__creation_date = datetime.datetime.now()
        self.__timeout = timeout
        self.__callback = callback
        self.__domain = domain
        if isinstance(role, str):
            role_set = {role}
        elif isinstance(role, list):
            role_set = set(role)
        else:
            role_set = role
        self.__roles: Optional[set] = role_set

        self.__event_attente = asyncio.Event()

        stream_queue = None
        if stream:  # Set up streaming responses
            stream_queue = asyncio.Queue(maxsize=3)
        self.__stream_queue: Optional[asyncio.Queue] = stream_queue

        self.__reponse: Optional[MessageWrapper] = None
        self.__consumed = False
        self.__cancelled = False

    @property
    def domain(self) -> Optional[Union[str, list]]:
        return self.__domain

    @property
    def roles(self) -> Optional[set]:
        return self.__roles

    @property
    def streaming(self) -> bool:
        return self.__stream_queue is not None

    @property
    def done(self) -> bool:
        return self.__event_attente.is_set()

    @property
    def has_callback(self):
        return self.__callback is not None

    @property
    def consumed(self):
        return self.__consumed

    async def wait(self, timeout=CONST_WAIT_REPLY_DEFAULT) -> MessageWrapper:
        self.__timeout = timeout or CONST_WAIT_REPLY_DEFAULT
        try:
            await asyncio.wait_for(self.__event_attente.wait(), timeout)
        except asyncio.TimeoutError as e:
            if self.__event_attente.is_set():
                self.__logger.error("Erreur timeout correlation %s, set pas triggered" % self.correlation_id)
            raise e

        if self.__cancelled:
            raise CancelledException()

        self.__consumed = True
        return self.__reponse

    async def stream_reponse(self, timeout=CONST_WAIT_REPLY_DEFAULT):
        if self.__stream_queue is None:
            raise Exception('Streaming not set')

        self.__timeout = timeout or CONST_WAIT_REPLY_DEFAULT
        while self.__event_attente.is_set() is False:
            valeur = await asyncio.wait_for(self.__stream_queue.get(), timeout)
            if self.__cancelled:
                raise CancelledException()
            if valeur is None:
                break
            yield valeur

        self.__consumed = True

    async def stream_to_callback_thread(self):
        """
        Start this thread to pipe the responses to the callback.
        :return:
        """
        try:
            async for message in self.stream_reponse(self.__timeout):
                await self.__callback(self.correlation_id, message)
        except TimeoutError:
            self.__logger.debug("Stream timeout")
        finally:
            self.__event_attente.set()
            self.__consumed = True

    async def handle_response(self, message: MessageWrapper):
        self.__reponse = message
        if self.__stream_queue is not None:
            # Verifier si on a l'attachement "streaming=True", indique que le stream n'est pas termine
            try:
                await asyncio.wait_for(self.__stream_queue.put(message), 0.5)
                self.__creation_date = datetime.datetime.now()  # Reset expiration
                if message.original['attachements']['streaming'] is True:
                    pass  # Continue streaming
            except (TypeError, AttributeError, KeyError):
                # Streaming done
                self.__event_attente.set()
                await asyncio.wait_for(self.__stream_queue.put(message), 0.5)
                await self.__stream_queue.put(None)  # Exit condition
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
        if self.__timeout is None:
            return True

        if self.__consumed is False:
            # On donne un delai supplementaire si la reponse n'est pas consommee
            duree_message = datetime.timedelta(seconds=self.__timeout * 3)
        else:
            duree_message = datetime.timedelta(seconds=self.__timeout)

        date_expiration = datetime.datetime.now() - duree_message

        return self.__creation_date < date_expiration

    async def cancel(self):
        if self.__consumed is False:
            self.__logger.debug("Correlation reponse %s annulee par le consumer" % self.correlation_id)
            self.__cancelled = True
            self.__event_attente.set()


class MilleGrillesPikaReplyQueueConsumer(MilleGrillesPikaQueueConsumer):

    def __init__(self, context: MilleGrillesBusContext):
        self.__logger = logging.getLogger(__name__+'.'+self.__class__.__name__)
        super().__init__(context, self.__on_reply_message, exclusive=True)
        self.__correlations: dict[str, MessageCorrelation] = dict()
        self.__group: Optional[TaskGroup] = None

    async def run(self):
        async with TaskGroup() as group:
            self.__group = group
            group.create_task(super().run())
            group.create_task(self.__thread_maintain_correlations())
        self.__group = None
        self.__logger.info("MilleGrillesPikaReplyQueueConsumer %s thread closed" % self.name)

    async def __thread_maintain_correlations(self):
        while self._context.stopping is False:
            # List expired correlation ids
            expired_ids = list()
            for c in self.__correlations.values():
                if c.expired():
                    expired_ids.append(c.correlation_id)
                    await c.cancel()
                elif c.consumed:
                    # Cleanup for unaffiliated streaming tasks
                    expired_ids.append(c.correlation_id)

            for expired_id in expired_ids:
                try:
                    del self.__correlations[expired_id]
                except KeyError:
                    pass

            await self._context.wait(5)

    async def __on_reply_message(self, message: MessageWrapper):
        # Verify message
        correlation_id = message.correlation_id
        if correlation_id is None:
            self.__logger.info("REPLY MESSAGE DROPPED: no correlation")
            return

        correlation = self.__correlations.get(correlation_id)
        try:
            if correlation is None:
                return  # Message gone, finally block will handle cleanup

            if correlation.streaming is False:
                # Preemptively remove - not streaming and we got the response
                del self.__correlations[correlation_id]

            # Check certificate against expected domain/role
            try:
                certificate = message.certificat
                if correlation.roles:
                    if correlation.roles.isdisjoint(certificate.get_roles):
                        self.__logger.info("REPLY MESSAGE DROPPED: role mismatch for %s" % correlation_id)
                        await correlation.cancel()
                        return
                elif correlation.domain:
                    if isinstance(correlation.domain, list):
                        domains = correlation.domain
                    elif isinstance(correlation.domain, str):
                        domains = [correlation.domain]
                    else:
                        self.__logger.info("REPLY MESSAGE DROPPED: domain types mismatch for %s" % correlation_id)
                        return

                    certificate_domains = certificate.get_domaines
                    if any([d in certificate_domains for d in domains]) is False:
                        self.__logger.info("REPLY MESSAGE DROPPED: domain mismatch for %s (%s vs %s)", correlation_id, certificate_domains, domains)
                        await correlation.cancel()
                        return

                await correlation.handle_response(message)

            except ExtensionNotFound:
                self.__logger.info("REPLY MESSAGE DROPPED: invalid domain/role for %s" % correlation_id)
                await correlation.cancel()
                return
            finally:
                if correlation.done:
                    try:
                        del self.__correlations[correlation_id]
                    except KeyError:
                        pass  # Already removed

            correlation = None
        except KeyError:
            self.__logger.info("REPLY MESSAGE DROPPED: unknown correlation_id %s" % correlation_id)
        finally:
            if correlation:
                # Reply not properly processed
                await correlation.cancel()

    def add_correlation(self, correlation: MessageCorrelation, run_thread=False):
        self.__correlations[correlation.correlation_id] = correlation
        if run_thread:
            if correlation.has_callback is False:
                raise ValueError("The correlation needs a callback to be deployed in a thread")
            self.__group.create_task(correlation.stream_to_callback_thread())

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
