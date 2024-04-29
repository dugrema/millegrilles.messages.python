# Plug-in module pour pika 1.2 dans millegrilles messages
import asyncio
import logging
import pika
import ssl

from typing import Optional, Union

from pika.adapters.asyncio_connection import AsyncioConnection
from pika.adapters.utils.connection_workflow import AMQPConnectionWorkflowFailed
from pika.channel import Channel
from redis.exceptions import ConnectionError

from millegrilles_messages.chiffrage.DechiffrageUtils import dechiffrer_reponse
from millegrilles_messages.messages import Constantes
from millegrilles_messages.messages.CleCertificat import CleCertificat
from millegrilles_messages.messages.EnveloppeCertificat import EnveloppeCertificat
from millegrilles_messages.messages.MessagesModule \
    import MessagesModule, MessageConsumerVerificateur, MessageProducerFormatteur, RessourcesConsommation, \
    MessageWrapper, MessagePending
from millegrilles_messages.messages.ParamsEnvironnement import ConfigurationPika
from millegrilles_messages.messages.ValidateurMessage import ValidateurMessage
from millegrilles_messages.messages.ValidateurCertificats import ValidateurCertificatRedis, ValidateurCertificatCache

CONSTANT_Q_TTL_ARGNAME = 'x-message-ttl'


class PikaModule(MessagesModule):

    def __init__(self):
        super(MessagesModule, self).__init__()
        super(PikaModule, self).__init__()
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self.__pika_configuration: Optional[ConfigurationPika] = None
        self.__connexion: Optional[AsyncioConnection] = None
        self.__channel_main: Optional[Channel] = None
        self.__exchanges_pending: Optional[set] = None

        self.__sync_connect = asyncio.Event()

        self.__connexions = list()
        self.__clecert: Optional[CleCertificat] = None
        self._enveloppe_ca: Optional[EnveloppeCertificat] = None

    def est_connecte(self) -> bool:
        return self.__connexion is not None

    async def preparer_ressources(self, env_configuration: Optional[dict] = None,
                                  reply_res: Optional[RessourcesConsommation] = None,
                                  consumers: Optional[list] = None,
                                  exchanges: Optional[list] = None):

        self.__pika_configuration = ConfigurationPika()
        self.__pika_configuration.parse_config(env_configuration)

        self._exchanges = exchanges

        self._enveloppe_ca = EnveloppeCertificat.from_file(self.__pika_configuration.ca_pem_path)

        try:
            validateur_certificats = ValidateurCertificatRedis(self._enveloppe_ca, configuration=env_configuration)
            await validateur_certificats.entretien()  # Connecter redis
        except (FileNotFoundError, ConnectionError, KeyError) as e:
            self.__logger.warning("Erreur configuraiton ou connexion a redis - fallback sur validateur avec cache memoire")
            if self.__logger.isEnabledFor(logging.INFO):
                self.__logger.exception("Erreur configuration redis")
            validateur_certificats = ValidateurCertificatCache(self._enveloppe_ca)

        validateur_messages = ValidateurMessage(validateur_certificats)

        self._validateur_certificats = validateur_certificats
        self._validateur_messages = validateur_messages

        enveloppe_cert = EnveloppeCertificat.from_file(self.__pika_configuration.cert_pem_path)
        fingerprint = enveloppe_cert.fingerprint

        # Creer producer
        self._producer = PikaModuleProducer(self, self._enveloppe_ca)
        validateur_certificats.set_producer_messages(self._producer)  # Wiring pour requete certificats

        # Conserver clecert pour dechiffrage reponses
        self.__clecert = CleCertificat.from_files(self.configuration.key_pem_path, self.configuration.cert_pem_path)

        # Creer reply-q, consumer
        if reply_res:
            reply_res.ajouter_rk(Constantes.SECURITE_PUBLIC, 'requete.certificat.%s' % fingerprint)
            reply_q_consumer = PikaModuleConsumer(self, reply_res)
            self.ajouter_consumer(reply_q_consumer, True)
            self._producer.set_reply_consumer(reply_q_consumer)

        if consumers is not None:
            for consumer_res in consumers:
                consumer = PikaModuleConsumer(self, consumer_res)
                self.ajouter_consumer(consumer)

    def dechiffrer_reponse(self, message: dict) -> dict:
        return dechiffrer_reponse(self.__clecert, message)

    async def entretien(self, event_stop: asyncio.Event):
        await super().entretien(event_stop)

        if self.__connexion is not None:
            if self.__connexion is not None and self.__connexion.is_closing or self.__connexion.is_closed:
                self.__logger.info("entretien Connexion fermee - on ferme l'application")
                await self._close()
                raise Exception('connexion fermee')

            if self.__channel_main is None:
                self.__logger.info("entretien Channel main ferme - on ferme l'application")
                await self._close()
                raise Exception('channel main ferme')
            else:
                if len(self.__channel_main.consumer_tags) == 0:
                    self.__logger.error("Channel main sans consumer tags - on ferme l'application")
                    await self._close()
                    raise Exception('entretien Channel main sans consumer tags')

            for consumer in self.get_consumers():
                if consumer.erreur_channel is True:
                    raise Exception('consumer avec channel en erreur')

        await self._validateur_certificats.entretien()

    def open_channel(self, on_open_callback):
        self.__connexion.channel(on_open_callback=on_open_callback)

    async def _connect(self):
        self.__logger.debug("Connecter a MQ avec configuration %s" % self.__pika_configuration)

        if self.__connexion is not None:
            raise Exception('Connexion existante')

        hostname = self.__pika_configuration.hostname

        # Extraire IDMG du certificat. C'est le virtual host RabbitMQ.
        enveloppe_cert = EnveloppeCertificat.from_file(self.__pika_configuration.cert_pem_path)
        idmg = enveloppe_cert.idmg

        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        tls_context.verify_mode = ssl.CERT_REQUIRED
        tls_context.load_verify_locations(self.__pika_configuration.ca_pem_path)
        tls_context.load_cert_chain(self.__pika_configuration.cert_pem_path, self.__pika_configuration.key_pem_path)
        ssl_options = pika.SSLOptions(tls_context, hostname)

        parameters = [
            pika.ConnectionParameters(host=hostname,
                                      port=self.__pika_configuration.port,
                                      virtual_host=idmg,
                                      credentials=pika.credentials.ExternalCredentials(),
                                      ssl_options=ssl_options,
                                      connection_attempts=self.__pika_configuration.connection_attempts,
                                      retry_delay=self.__pika_configuration.retry_delay,
                                      heartbeat=self.__pika_configuration.heartbeat,
                                      blocked_connection_timeout=self.__pika_configuration.blocked_connection_timeout)]

        connection_adapter = AsyncioConnection.create_connection(parameters, on_done=self.on_connect_done)

        self.__logger.debug("Connection adapter : %s", connection_adapter)

    async def _close(self):
        self._consuming = False

        try:
            await MessagesModule._close(self)
        except Exception:
            self.__logger.exception("Erreur MessagesModule._close")

        if self.__channel_main is not None:
            self.__channel_main.close(reply_text='PikaModule._close() channel')
            self.__channel_main = None

        if self.__connexion is None:
            self.__logger.info('Connection already closed')
            return

        if self.__connexion.is_closing or self.__connexion.is_closed:
            self.__logger.info('Connection is closing or already closed')
        else:
            self.__logger.info('Closing connection %s' % self.__connexion)
            self.__connexion.close(reply_text='PikaModule._close()')

        # self.__connexion = None

    def on_connect_done(self, connexion: Union[AsyncioConnection, AMQPConnectionWorkflowFailed] = None):
        if isinstance(connexion, AMQPConnectionWorkflowFailed):
            try:
                self.__logger.error("Erreur de connexion a MQ : %s" % connexion.exceptions)
            except:
                self.__logger.error("Erreur de connexion a MQ : %s" % connexion)
            # self.__connexion = None
        else:
            self.__connexions.append(connexion)

            if self.__connexion is not None:
                self.__logger.warning('Connexion MQ deja presente - on la ferme sur reception de nouvelle')
                connexion_existante = self.__connexion
                if not (connexion_existante.is_closed or connexion_existante.is_closing):
                    connexion_existante.close(reply_text='PikaModule ERROR duplication connexion received')

            self.__logger.debug("Connexion a MQ reussi %s" % connexion)
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
            if res.channel_separe is True:
                consumer.clear_channel()

    def on_close(self, _unused_connection, reason):
        self.__logger.info("on_close: Connexion fermee, raison : %s", reason)
        self.__channel_main = None
        self.__connexion = None

    @property
    def configuration(self) -> ConfigurationPika:
        return self.__pika_configuration

    async def start_consumer(self, nom_q: str):
        for consumer in self.get_consumers():
            if consumer.q == nom_q:
                consumer.start_consuming()

    async def stop_consumer(self, nom_q: str):
        for consumer in self.get_consumers():
            if consumer.q == nom_q:
                consumer.stop_consuming()


class PikaModuleConsumer(MessageConsumerVerificateur):

    def __init__(self, module_messages: PikaModule, ressources: RessourcesConsommation):

        super().__init__(module_messages, ressources)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__channel: Optional[Channel] = None

        self.__pika_module = module_messages

        self.__consumer_tag: Optional[str] = None

        self.__rk_pending = set()

        self.__enveloppe_certificat: Optional[EnveloppeCertificat] = None
        self.__rk_certificat: Optional[str] = None

    def set_enveloppe_certificat(self, enveloppe_certificat: EnveloppeCertificat):
        self.__enveloppe_certificat = enveloppe_certificat
        self.__rk_certificat = 'requete.certificat.%s' % enveloppe_certificat.fingerprint

    def set_channel(self, channel: Channel):
        self.__channel = channel
        self.__channel.add_on_cancel_callback(self.on_consumer_cancelled)
        channel.add_on_close_callback(self.clear_channel)
        self._event_channel.set()

    def clear_channel(self, _channel=None, reason='clear channel'):
        if self.__channel is not None:
            self._erreur_channel = True
            try:
                self.__channel.close(reply_text=reason)
            except pika.exceptions.ChannelWrongStateError:
                pass  # OK
        self.__channel = None

    def enregistrer_ressources(self):
        if self._ressources.channel_separe is True:
            if self._ressources.actif is True:
                self.__pika_module.open_channel(self.on_channel_open)
            else:
                # Indiquer que le consumer est pret meme si on n'a aucuns ressources (il est inactif)
                self._consumer_pret.set()
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
            if exclusive:
                # TTL 1 heure par defaut sur Q exclusive
                try:
                    if arguments.get(CONSTANT_Q_TTL_ARGNAME) is None:
                        arguments = arguments.copy()
                        arguments[CONSTANT_Q_TTL_ARGNAME] = 3_600_000
                except AttributeError:
                    arguments = {CONSTANT_Q_TTL_ARGNAME: 3_600_000}
            self.__channel.queue_declare(nom_q, exclusive=exclusive, callback=self.on_queue_declare,
                                         durable=durable, auto_delete=auto_delete, arguments=arguments)
        elif reply_q is False:
            # On utilise une queue existante (RK deja configures)
            self.set_qos()

    def set_qos(self):
        self.__channel.basic_qos(prefetch_count=self._ressources.prefetch_count, callback=self.on_basic_qos_ok)

    def start_consuming(self):
        if self.__consumer_tag is None:
            self._ressources.actif = True
            if self.__channel is None:
                # Le channel n'a pas ete cree (thread = False)
                # Creer channel et attendre callback
                self.__pika_module.open_channel(self.on_channel_open)
                return  # On va avoir un callback via set_qos

            self.__consumer_tag = self.__channel.basic_consume(self._ressources.q, self.on_message)
            self._event_consumer.set()
            self._consumer_pret.set()
        else:
            self.__logger.debug('start_consuming Consuming deja actif')

    def stop_consuming(self):
        self._ressources.actif = False
        if self.__consumer_tag is not None:
            self.__channel.basic_cancel(self.__consumer_tag, self.on_cancel_ok)

    def on_channel_open(self, channel: Channel):
        self.set_channel(channel)
        channel.add_on_close_callback(self.clear_channel)
        self.enregistrer_q()

    def on_basic_qos_ok(self, _unused_frame):
        if self._ressources.actif:
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
        self.__channel.close(reply_text="Consumer cancelled")
        self._event_consumer.clear()
        self.__consumer_tag = None

    def on_cancel_ok(self, data):
        self.__logger.debug("Cancel consumer ok: %s" % data)
        self._event_consumer.clear()
        self.__consumer_tag = None

    def on_message(self, _unused_channel, basic_deliver, properties, body):
        self.__logger.debug("Message recu : %s" % properties)

        if self.__consumer_tag is None:
            self.__logger.warning("Message recu sur %s, pas mode consuming - NACK", self.q)
            self.__channel.basic_nack(basic_deliver.delivery_tag)
            return

        # Traiter via une task asyncio
        correlation_id = properties.correlation_id
        reply_to = properties.reply_to
        exchange = basic_deliver.exchange
        routing_key = basic_deliver.routing_key
        delivery_tag = basic_deliver.delivery_tag

        message = MessageWrapper(body, routing_key, self._ressources.q, exchange, reply_to, correlation_id, delivery_tag)

        if routing_key == self.__rk_certificat:
            # Intercepter le message, repondre avec notre certificat
            self.repondre_certificat(message)
            return

        # Note : recevoir va lancer une exception si le message precedent n'est pas fini de traiter
        self.recevoir_message(message)

    def ack_message(self, message: MessageWrapper):
        self.__channel.basic_ack(message.delivery_tag)

    @property
    def q(self):
        return self._ressources.q

    def ajouter_routing_key(self, exchange: str, rk: str):
        if not self.__channel:
            raise Exception('channel pas pret')

        def callback_binding(_unused_frame, self=self, nom_queue=self.q, rk=rk):
            self.__logger.debug("Resultat binding OK: %s sur %s" % (nom_queue, rk))

        self.__channel.queue_bind(self.q, exchange, rk, callback=callback_binding)

    def retirer_routing_key(self, exchange: str, rk: str):
        if not self.__channel:
            raise Exception('channel pas pret')

        def callback_binding(_unused_frame, self=self, nom_queue=self.q, rk=rk):
            self.__logger.debug("Resultat unbinding OK: %s sur %s" % (nom_queue, rk))

        self.__channel.queue_unbind(self.q, exchange, rk, callback=callback_binding)


class PikaModuleProducer(MessageProducerFormatteur):

    def __init__(self, pika_module: PikaModule, enveloppe_ca: EnveloppeCertificat):
        configuration = pika_module.configuration
        clecert = CleCertificat.from_files(configuration.key_pem_path, configuration.cert_pem_path)

        super().__init__(pika_module, clecert, enveloppe_ca)

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__channel: Optional[Channel] = None

    def set_channel(self, channel: Channel):
        self.__channel = channel
        channel.add_on_close_callback(self.clear_channel)
        event_loop = self._module_messages.get_event_loop()
        event_loop.call_soon_threadsafe(self._producer_pret.set)

    def clear_channel(self, _channel=None, reason=None):
        self.__logger.debug("Fermeture channel producer : %s", reason)
        try:
            self.__channel.close(reply_text='producer clear_channel')
        except (AttributeError, pika.exceptions.ChannelWrongStateError):
            pass  # OK
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
            for exchange in exchanges:
                self.__channel.basic_publish(
                    exchange=exchange,
                    routing_key=routing_key,
                    body=message.content,
                    properties=properties,
                    mandatory=True
                )
        else:
            self.__channel.basic_publish(
                exchange='',
                routing_key=routing_key,
                body=message.content,
                properties=properties,
                mandatory=True
            )

