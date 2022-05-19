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
    MessageWrapper, MessagePending


class PikaModule(MessagesModule):

    def __init__(self):
        super(MessagesModule, self).__init__()
        super(PikaModule, self).__init__()
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self.__connexion: Optional[AsyncioConnection] = None
        self.__channel_main: Optional[Channel] = None
        self.__exchanges_pending: Optional[set] = None

    def est_connecte(self) -> bool:
        return self.__connexion is not None

    def preparer_ressources(self, reply_res: Optional[RessourcesConsommation] = None, consumers: Optional[list] = None,
                            exchanges: Optional[list] = None):

        self._exchanges = exchanges

        # Creer reply-q, consumer
        if reply_res:
            reply_q_consumer = PikaModuleConsumer(self, reply_res)
            self.ajouter_consumer(reply_q_consumer)

        if consumers is not None:
            for consumer_res in consumers:
                consumer = PikaModuleConsumer(self, consumer_res)
                self.ajouter_consumer(consumer)

        # Creer producer
        self._producer = PikaModuleProducer(self, reply_res)

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

        if self._exchanges is not None:
            # Recreer les exchanges en premier
            self.__exchanges_pending = set()
            self.__exchanges_pending.update(self._exchanges)

            for ex in self.__exchanges_pending:

                def callback_binding(_unused_frame, self=self, exchange=ex):
                    self.__logger.debug("Resultat exchange OK: %s" % exchange)
                    self.__exchanges_pending.remove(exchange)

                    if len(self.__exchanges_pending) == 0:
                        self.__logger.info("Exchanges prets")
                        self.demarrer_ressources()

                self.__channel_main.exchange_declare(ex.nom, ex.type_exchange, durable=True,
                                                     callback=callback_binding)

        else:
            # Reconfigurer les producers/listeners
            self.demarrer_ressources()

    def demarrer_ressources(self):
        """
        Generer les ressources pour consumers et le producer
        :return:
        """
        self._producer.set_channel(self.__channel_main)
        for consumer in self._consumers:
            res = consumer.get_ressources()
            if res.channel_separe is not True:
                consumer.set_channel(self.__channel_main)
            consumer.enregistrer_ressources()

    def on_channel_closed(self, _channel, reason):
        self.__channel_main = None
        self.__logger.debug("Channel closed, reason : %s", reason)

        self._producer.clear_channel()
        for consumer in self._consumers:
            res = consumer.get_ressources()
            if res.channel_separe is not True:
                consumer.clear_channel()

    def on_close(self, _unused_connection, reason):
        self.__logger.info("on_close: Connexion fermee, raison : %s", reason)
        self.__channel_main = None
        self.__connexion = None


class PikaModuleConsumer(MessageConsumerVerificateur):

    def __init__(self, module_messages: PikaModule, ressources: RessourcesConsommation):

        super().__init__(module_messages, ressources)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__channel: Optional[Channel] = None

        self.__pika_module = module_messages

        self.__consumer_tag: Optional[str] = None

        self.__rk_pending = set()

    def set_channel(self, channel: Channel):
        self.__channel = channel
        channel.add_on_close_callback(self.clear_channel)
        self._event_channel.set()

    def clear_channel(self, _channel=None, reason=None):
        self.__channel = None

    def enregistrer_ressources(self):
        if self._ressources.channel_separe is True:
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
            exclusive = reply_q is True or self._ressources.exclusive
            durable = self._ressources.durable
            auto_delete = self._ressources.auto_delete
            arguments = self._ressources.arguments
            self.__channel.queue_declare(nom_q, exclusive=exclusive, callback=self.on_queue_declare,
                                         durable=durable, auto_delete=auto_delete, arguments=arguments)
        elif reply_q is False:
            # On utilise une queue existante (RK deja configures)
            self.set_qos()

    def set_qos(self):
        self.__channel.basic_qos(prefetch_count=self._ressources.prefetch_count, callback=self.on_basic_qos_ok)

    def start_consuming(self):
        self.__channel.add_on_cancel_callback(self.on_consumer_cancelled)
        self.__consumer_tag = self.__channel.basic_consume(self._ressources.q, self.on_message)
        self._event_consumer.set()
        self._consumer_pret.set()

    def stop_consuming(self):
        self.__channel.basic_cancel(self.__consumer_tag, self.on_cancel_ok)
        self._event_consumer.clear()
        self._consumer_pret.clear()
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

        routing_keys = self._ressources.rk
        if routing_keys is not None:
            # Enregistrer bindings
            self.__rk_pending.update(routing_keys)
            for rk in self.__rk_pending:

                def callback_binding(_unused_frame, self=self, nom_queue=nom_queue, rk=rk):
                    self.__logger.debug("Resultat binding OK: %s sur %s" % (nom_queue, rk))
                    self.__rk_pending.remove(rk)

                    if len(self.__rk_pending) == 0:
                        self.__logger.info("Bindings Q %s prets" % nom_queue)
                        self.set_qos()

                self.__logger.debug("Binding %s sur %s" % (rk, nom_queue))
                self.__channel.queue_bind(nom_queue, rk.exchange, rk.rk, callback=callback_binding)
        else:
            # Set qos et demarrer consommation
            self.set_qos()

    # def on_bindok(self, data):
    #     self.__logger.debug("Binding OK pour %s", data)

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

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__channel: Optional[Channel] = None

    def set_channel(self, channel: Channel):
        self.__channel = channel
        channel.add_on_close_callback(self.clear_channel)
        self._producer_pret.set()

    def clear_channel(self, _channel=None, reason=None):
        self.__logger.debug("Fermeture channel producer : %s", reason)
        self.__channel = None
        self._producer_pret.clear()

    async def send(self, message: MessagePending):
        if self.__channel is None:
            raise Exception("Channel n'est pas pret")

        exchanges = message.exchanges
        routing_key = message.routing_key
        reply_to = message.reply_to
        correlation_id = message.correlation_id
        headers = message.headers

        delivery_mode_v = 1

        properties = pika.BasicProperties(delivery_mode=delivery_mode_v)
        if reply_to is not None:
            properties.reply_to = reply_to
        if correlation_id is not None:
            properties.correlation_id = correlation_id
        if headers:
            properties.headers = headers

        if exchanges is not None:
            raise NotImplementedError('todo')
        else:
            self.__channel.basic_publish(
                exchange='',
                routing_key=routing_key,
                body=message.content,
                properties=properties,
                mandatory=True
            )

