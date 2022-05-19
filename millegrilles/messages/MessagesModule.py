import logging
import asyncio

from threading import Event as EventThreading
from typing import Optional, Union

from asyncio import Event
from asyncio.exceptions import TimeoutError


class RessourcesConsommation:

    def __init__(self, callback, nom_queue: Optional[str] = None,
                 channel_separe=False, est_asyncio=False, prefetch_count=1, auto_delete=False, exclusive=False, durable=False):
        """
        Pour creer une reply-Q, laisser nom_queue vide.
        Pour configurer une nouvelle Q, inlcure une liste de routing_keys avec le nom de la Q.
        :param nom_queue:
        :param routing_keys:
        """
        self.callback = callback
        self.q = nom_queue  # Param est vide, le nom de la Q va etre conserve lors de la creation de la reply-Q
        self.rk: Optional[list] = None
        self.est_reply_q = self.q is None
        self.est_asyncio = est_asyncio
        self.channel_separe = channel_separe
        self.prefetch_count = prefetch_count
        self.exclusive = exclusive
        self.durable = durable
        self.auto_delete = auto_delete
        self.arguments: Optional[dict] = None

    def ajouter_rk(self, exchange: str, rk: str):
        if self.rk is None:
            self.rk = list()
        self.rk.append(RessourcesRoutingKey(exchange, rk))

    def set_ttl(self, ttl: int):
        if self.arguments is None:
            self.arguments = dict()
        self.arguments['x-message-ttl'] = ttl


class RessourcesRoutingKey:

    def __init__(self, exchange: str, rk: str):
        self.exchange = exchange
        self.rk = rk

    def __str__(self):
        return 'RessourcesRoutingKey %s/%s' % (self.exchange, self.rk)

    def __hash__(self):
        return hash('.'.join([self.exchange, self.rk]))

    def __eq__(self, other):
        return other.exchange == self.exchange and other.rk == self.rk


class MessagesModule:

    def __init__(self):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self._consumers = list()
        self._producer = None

        self.__event_pret = EventThreading()

        self.__event_attente: Optional[Event] = None

    async def __entretien_task(self):
        self.__event_attente = Event()

        while not self.__event_attente.is_set():
            await self.entretien()

            try:
                await asyncio.wait_for(self.__event_attente.wait(), 30)
            except TimeoutError:
                pass

    async def entretien(self):
        if self.est_connecte() is True:
            self.__logger.debug("Verifier etat connexion MQ")

        if self.est_connecte() is False:
            self.__logger.debug("Connecter MQ")
            await self._connect()

    async def run_async(self):
        # Creer tasks pour producers, consumers et entretien
        tasks = [
            asyncio.create_task(self.__entretien_task()),
            asyncio.create_task(self._producer.run_async()),
        ]

        for consumer in self._consumers:
            tasks.append(asyncio.create_task(consumer.run_async()))

        # Execution de la loop avec toutes les tasks
        await asyncio.tasks.wait(tasks, return_when=asyncio.tasks.FIRST_COMPLETED)

    def est_connecte(self) -> bool:
        raise NotImplementedError('Not implemented')

    async def _connect(self):
        raise NotImplementedError('Not implemented')

    async def _close(self):
        raise NotImplementedError('Not implemented')

    def ajouter_consumer(self, consumer: RessourcesConsommation):
        self._consumers.append(consumer)

    def preparer_ressources(self, reply_res: Optional[RessourcesConsommation] = None, consumers: Optional[list] = None):
        raise NotImplementedError('Not implemented')

    def get_producer(self):
        return self._producer

    def get_consumers(self):
        return self._consumers

    def attendre_pret(self, max_delai=20):
        event_producer = self._producer.producer_pret()
        event_producer.wait(max_delai)

        if event_producer.is_set() is False:
            raise Exception("Timeout attente producer")

        for consumer in self._consumers:
            event = consumer.consumer_pret()
            event.wait(max_delai)

            if event.is_set() is False:
                raise Exception("Timeout attente consumer")


class MessageWrapper:

    def __init__(self, contenu: bytes, routing_key: str, queue: str, exchange: str, reply_to: str, correlation_id: str, delivery_tag: int):
        self.contenu = contenu
        self.routing_key = routing_key
        self.queue = queue
        self.exchange = exchange
        self.reply_to = reply_to
        self.correlation_id = correlation_id
        self.delivery_tag = delivery_tag

        # Message traite et verifie
        self.parsed: Optional[dict] = None
        self.certificat_pem: Optional[list] = None
        self.millegrille_pem: Optional[str] = None
        self.certificat = None
        self.hachage_valide = False
        self.signature_valide = False
        self.certificat_valide = False

    def __str__(self):
        return 'tag:%d' % self.delivery_tag


class MessageConsumer:
    """
    Consumer pour une Q.
    """

    def __init__(self, module_messages: MessagesModule, ressources: RessourcesConsommation):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self._module_messages = module_messages
        self._ressources = ressources

        # self._consuming = False
        self.__loop = None
        self._event_channel: Optional[Event] = None
        self._event_consumer: Optional[Event] = None
        self._event_message: Optional[Event] = None

        # Q de messages en memoire
        self._messages = list()

        self._consumer_pret = EventThreading()

    async def run_async(self):
        self.__logger.info("Demarrage consumer %s" % self._module_messages)

        # Setup asyncio
        self.__loop = asyncio.get_event_loop()
        self._event_channel = Event()
        self._event_consumer = Event()
        self._event_message = Event()

        # Attente ressources
        await self._event_channel.wait()
        await self._event_consumer.wait()

        self.__logger.info("Consumer actif")
        while self._event_consumer.is_set():
            self._event_message.clear()
            # Traiter messages
            while len(self._messages) > 0:
                message = self._messages.pop(0)
                await self.__traiter_message(message)
            await self._event_message.wait()

        self._consumer_pret.clear()
        self.__logger.info("Arret consumer %s" % self._module_messages)

    def recevoir_message(self, message: MessageWrapper):
        self.__logger.debug("recevoir_message")
        self._messages.append(message)

        # call_soon_threadsafe permet d'interagir avec asyncio a partir d'une thread externe
        # Requis pour demarrer le traitement des messages immediatement
        self.__loop.call_soon_threadsafe(self._event_message.set)

    async def __traiter_message(self, message: MessageWrapper):
        # Clear flag, permet de s'assurer de bloquer sur un message en attente
        try:
            self.__logger.debug("Message a traiter : %s" % message.delivery_tag)
            await self._traiter_message(message)
        finally:
            # Debloquer Q pour le prochain message
            self.__logger.debug("Message traite, ACK %s" % message.delivery_tag)
            self.ack_message(message)

    async def _traiter_message(self, message):
        # Effectuer le traitement
        if self._ressources.est_asyncio is True:
            await self._ressources.callback(message)
        else:
            # Utiliser threadpool de asyncio pour methode blocking
            await asyncio.to_thread(self._ressources.callback, message)

    def get_ressources(self):
        return self._ressources

    def ack_message(self, message: MessageWrapper):
        raise NotImplementedError('Not implemented')

    def consumer_pret(self) -> EventThreading:
        return self._consumer_pret


class MessageConsumerVerificateur(MessageConsumer):

    def __init__(self, module_messages: MessagesModule, ressources: RessourcesConsommation):
        super().__init__(module_messages, ressources)


class MessagePending:

    def __init__(self, content: bytes, routing_key: str, exchanges: list, reply_to=None, correlation_id=None, headers: Optional[dict] = None):
        self.content = content
        self.routing_key = routing_key
        self.reply_to = reply_to
        self.correlation_id = correlation_id
        self.exchanges = exchanges
        self.headers = headers


class MessageProducer:

    def __init__(self, module_messages: MessagesModule, reply_res: Optional[RessourcesConsommation] = None):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self._module_messages = module_messages
        self._reply_res = reply_res

        self._message_number = 0
        self.__deliveries = list()  # Q d'emission de message, permet d'emettre via thread IO-LOOP

        self.__loop = None
        self.__event_message: Optional[Event] = None
        self._event_q_prete = EventThreading()
        self.__NB_MESSAGE_MAX = 10

        self.__actif = False
        self._producer_pret = EventThreading()

    def emettre(self, message: Union[str, bytes], routing_key: str,
                exchanges: Optional[Union[str, list]] = None, correlation_id: str = None, reply_to: str = None):

        if not self._producer_pret.is_set():
            raise Exception("Producer n'est pas pret (utiliser message thread ou producer .producer_pret().wait()")

        self._event_q_prete.wait()

        if isinstance(message, str):
            message = message.encode('utf-8')

        if isinstance(exchanges, str):
            exchanges = [exchanges]

        if reply_to is None:
            # Tenter d'injecter la reply_q
            if self._reply_res is not None:
                reply_to = self._reply_res.q

        pending = MessagePending(message, routing_key, exchanges, reply_to, correlation_id)
        self.__deliveries.append(pending)
        if len(self.__deliveries) > self.__NB_MESSAGE_MAX:
            self._event_q_prete.clear()  # Va faire bloquer le prochain appel

        # Notifier thread en await
        # self.__event_message.set()
        self.__loop.call_soon_threadsafe(self.__event_message.set)

    async def run_async(self):
        self.__logger.info("Demarrage run_async producer")
        self.__loop = asyncio.get_event_loop()
        self.__actif = True
        self.__event_message = Event()

        try:
            while self.__actif:
                while len(self.__deliveries) > 0:
                    message = self.__deliveries.pop(0)
                    self.__logger.debug("producer : send message %s" % message)
                    await self.send(message)

                self._event_q_prete.set()  # Debloque reception de messages

                # Attendre prochains messages
                await self.__event_message.wait()
                self.__logger.debug("Wake up producer")

                self.__event_message.clear()  # Reset flag
        except:
            self.__logger.exception("Erreur traitement, producer arrete")

        self.__actif = False

    async def send(self, message: MessagePending):
        self.__logger.warning("NOT IMPLEMENTED - Emettre message %s", message)

    def get_reply_q(self):
        return self._reply_res.q

    def producer_pret(self) -> EventThreading:
        return self._producer_pret


class MessageProducerFormatteur(MessageProducer):
    """
    Produceur qui formatte le message a emettre.
    """

    def __init__(self, module_messages: MessagesModule, reply_res: Optional[RessourcesConsommation] = None):
        super().__init__(module_messages, reply_res)

    def emettre_evenement(self, evenement: dict, domaine: str, action: str,
                          partition: Optional[str], exchanges: Union[str, list], version=1,
                          reply_to=None, correlation_id=None):
        pass

    def emettre_commande(self):
        pass

    def emettre_requete(self):
        pass

    def emettre_transaction(self):
        pass

    def repondre(self):
        pass
