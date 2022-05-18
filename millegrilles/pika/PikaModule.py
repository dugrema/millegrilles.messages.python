# Plug-in module pour pika 1.2 dans millegrilles messages
import asyncio
import logging
import pika
import ssl

from typing import Optional, Union

from pika.adapters.asyncio_connection import AsyncioConnection
from pika.adapters.utils.connection_workflow import AMQPConnectionWorkflowFailed
from pika.channel import Channel

from millegrilles.messages.MessagesModule \
    import MessagesModule, MessageConsumerVerificateur, MessageProducerFormatteur, RessourcesConsommation, \
    MessageWrapper


class PikaModule(MessagesModule):

    def __init__(self):
        super(MessagesModule, self).__init__()
        super(PikaModule, self).__init__()
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self.__connexion: Optional[AsyncioConnection] = None
        self.__channel_main: Optional[Channel] = None

    def est_connecte(self) -> bool:
        return self.__connexion is not None

    def preparer_ressources(self):
        # Creer reply-q, consumer
        reply_q_ressources = RessourcesConsommation()
        reply_q_consumer = PikaModuleConsumer(self, reply_q_ressources, channel_separe=True)
        self._consumers.append(reply_q_consumer)

        # Creer producer
        self._producer = PikaModuleProducer(self, reply_q_ressources)

    async def entretien(self):
        await super().entretien()

        if self.__channel_main is None:
            self.__logger.info("Connecter channel main")

    def open_channel(self, on_open_callback):
        self.__connexion.channel(on_open_callback=on_open_callback)

    async def _connect(self):
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        tls_context.verify_mode = ssl.CERT_REQUIRED
        tls_context.load_verify_locations('/home/mathieu/mgdev/certs/pki.millegrille')
        tls_context.load_cert_chain('/home/mathieu/mgdev/certs/pki.core.cert', '/home/mathieu/mgdev/certs/pki.core.key')
        ssl_options = pika.SSLOptions(tls_context, 'mq')

        parameters = [
            pika.ConnectionParameters(host='mg-dev5.maple.maceroc.com',
                                      port=5673,
                                      virtual_host='zeYncRqEqZ6eTEmUZ8whJFuHG796eSvCTWE4M432izXrp22bAtwGm7Jf',
                                      credentials=pika.credentials.ExternalCredentials(),
                                      ssl_options=ssl_options,
                                      connection_attempts=2, retry_delay=10,
                                      heartbeat=30, blocked_connection_timeout=10)]

        connection_adapter = AsyncioConnection.create_connection(parameters, on_done=self.on_connect_done)

        self.__logger.debug("Connection adapter : %s", connection_adapter)

    async def _close(self):
        self._consuming = False

        if self.__connexion is None:
            self.__logger.info('Connection already closed')
            return

        if self.__connexion.is_closing or self.__connexion.is_closed:
            self.__logger.info('Connection is closing or already closed')
        else:
            self.__logger.info('Closing connection')
            self.__connexion.close()

        self.__connexion = None

    def on_connect_done(self, connexion: Union[AsyncioConnection, AMQPConnectionWorkflowFailed] = None):
        if isinstance(connexion, AMQPConnectionWorkflowFailed):
            self.__logger.error("Erreur de connexion a MQ : %s" % connexion.exceptions)
            self.__connexion = None
        else:
            self.__logger.debug("Connexion a MQ reussi")
            self.__connexion = connexion

            # Enregistrer callbacks
            self.__connexion.add_on_close_callback(self.on_close)

            # Ouvrir un channel
            self.__connexion.channel(on_open_callback=self.on_channel_open)

    def on_channel_open(self, channel: Channel):
        self.__channel_main = channel
        channel.add_on_close_callback(self.on_channel_closed)

        # Reconfigurer les producers/listeners
        self._producer.set_channel(self.__channel_main)
        for consumer in self._consumers:
            if consumer.channel_separe is not True:
                consumer.set_channel(self.__channel_main)
            consumer.enregistrer_ressources()

    def on_channel_closed(self, _channel, reason):
        self.__channel_main = None
        self.__logger.debug("Channel closed, reason : %s", reason)

        self._producer.clear_channel()
        for consumer in self._consumers:
            if consumer.channel_separe is not True:
                consumer.clear_channel()

    def on_close(self, _unused_connection, reason):
        self.__logger.info("on_close: Connexion fermee, raison : %s", reason)
        self.__channel_main = None
        self.__connexion = None


class PikaModuleConsumer(MessageConsumerVerificateur):

    def __init__(self, module_messages: PikaModule, ressources: RessourcesConsommation,
                 prefetch_count=2, channel_separe=False):

        super().__init__(module_messages, ressources, prefetch_count, channel_separe)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__channel: Optional[Channel] = None

        self.__pika_module = module_messages

        self.__consumer_tag: Optional[str] = None

    def set_channel(self, channel: Channel):
        self.__channel = channel
        channel.add_on_close_callback(self.clear_channel)
        self._event_channel.set()

    def clear_channel(self, _channel=None, reason=None):
        self.__channel = None

    def enregistrer_ressources(self):
        if self.channel_separe is True:
            self.__pika_module.open_channel(self.on_channel_open)
        else:
            self.enregistrer_q()

    def enregistrer_q(self):
        reply_q = self._ressources.est_reply_q
        if reply_q is True:
            nom_q = ''
        else:
            nom_q = self._ressources.q or ''
        rk = self._ressources.rk

        if reply_q is True or rk is not None:
            # On doit declarer la Q
            exclusive = reply_q is True
            self.__channel.queue_declare(nom_q, exclusive=exclusive, callback=self.on_queue_declare)
        elif reply_q is False:
            # On utilise une queue existante (RK deja configures)
            self.set_qos()

    def set_qos(self):
        self.__channel.basic_qos(prefetch_count=self._prefetch_count, callback=self.on_basic_qos_ok)

    def start_consuming(self):
        self.__channel.add_on_cancel_callback(self.on_consumer_cancelled)
        self.__consumer_tag = self.__channel.basic_consume(self._ressources.q, self.on_message)
        self._event_consumer.set()

    def stop_consuming(self):
        self.__channel.basic_cancel(self.__consumer_tag, self.on_cancel_ok)
        self._event_consumer.clear()
        self.__consumer_tag = None

    def on_channel_open(self, channel: Channel):
        self.set_channel(channel)
        self.enregistrer_q()

    def on_basic_qos_ok(self, _unused_frame):
        self.start_consuming()

    def on_queue_declare(self, queue):
        nom_queue = queue.method.queue
        self.__logger.debug("Q declaree : %s" % nom_queue)
        # Enregistrer bindings de routing_key
        self._ressources.q = nom_queue

        rk = self._ressources.rk
        if rk is not None:
            # Enregistrer bindings
            raise NotImplementedError("todo")
        else:
            # Set qos et demarrer consommation
            self.set_qos()

    def on_consumer_cancelled(self, method_frame):
        self.__logger.debug("Consumer cancelled")
        self._event_consumer.clear()
        self.__consumer_tag = None

    def on_cancel_ok(self, _unused_frame, data):
        self.__logger.debug("Cancel consumer ok: %s" % data)

    def on_message(self, _unused_channel, basic_deliver, properties, body):
        self.__logger.debug("Message recu : %s" % body)

        # Traiter via une task asyncio
        correlation_id = properties.correlation_id
        reply_to = properties.reply_to
        exchange = basic_deliver.exchange
        routing_key = basic_deliver.routing_key
        delivery_tag = basic_deliver.delivery_tag

        message = MessageWrapper(body, routing_key, self._ressources.q, exchange, reply_to, correlation_id, delivery_tag)

        # Note : recevoir va lancer une exception si le message precedent n'est pas fini de traiter
        self.recevoir_message(message)

    def ack_message(self, message: MessageWrapper):
        self.__channel.basic_ack(message.delivery_tag)


class PikaModuleProducer(MessageProducerFormatteur):

    def __init__(self, pika_module: PikaModule, reply_res: Optional[RessourcesConsommation] = None):
        super().__init__(pika_module, reply_res)
        self.__channel: Optional[Channel] = None

    def set_channel(self, channel: Channel):
        self.__channel = channel
        channel.add_on_close_callback(self.clear_channel)

    def clear_channel(self, _channel=None, reason=None):
        self.__channel = None
