import logging
import asyncio

from typing import Optional, Union

from asyncio import Event
from asyncio.exceptions import TimeoutError


class MessagesModule:

    def __init__(self):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self._consumers = list()
        self._producer = None

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

    def ajouter_consumer(self, consumer):
        self._consumers.append(consumer)

    def preparer_ressources(self, reply_callback, reply_callback_is_asyncio):
        raise NotImplementedError('Not implemented')


class RessourcesConsommation:

    def __init__(self, nom_queue: Optional[str] = None, routing_keys: Optional[list] = None):
        """
        Pour creer une reply-Q, laisser nom_queue vide.
        Pour configurer une nouvelle Q, inlcure une liste de routing_keys avec le nom de la Q.
        :param nom_queue:
        :param routing_keys:
        """
        self.q = nom_queue  # Param est vide, le nom de la Q va etre conserve lors de la creation de la reply-Q
        self.rk = routing_keys
        self.est_reply_q = self.q is None


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

    def __init__(self, module_messages: MessagesModule, ressources: RessourcesConsommation, callback,
                 prefetch_count=1, channel_separe=False, callback_is_asyncio=False):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self._module_messages = module_messages
        self._ressources = ressources
        self._callback = callback
        self._callback_is_async = callback_is_asyncio
        self.channel_separe = channel_separe

        # self._consuming = False
        self._prefetch_count = prefetch_count
        self._event_channel: Optional[Event] = None
        self._event_consumer: Optional[Event] = None
        self._event_message: Optional[Event] = None

        # Q de messages en memoire
        self._messages = list()

    async def run_async(self):
        self._event_channel = Event()
        self._event_consumer = Event()
        self._event_message = Event()
        self.__logger.info("Demarrage consumer %s" % self._module_messages)

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

        self.__logger.info("Arret consumer %s" % self._module_messages)

    async def entretien(self):
        pass

    def recevoir_message(self, message: MessageWrapper):
        self.__logger.debug("recevoir_message")
        self._messages.append(message)
        self._event_message.set()

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
        await asyncio.sleep(5)

        if self._callback_is_async is True:
            await self._callback(message)
        else:
            await asyncio.to_thread(self._callback, message)

    def ack_message(self, message: MessageWrapper):
        raise NotImplementedError('Not implemented')


class MessageConsumerVerificateur(MessageConsumer):

    def __init__(self, module_messages: MessagesModule, ressources: RessourcesConsommation, callback,
                 prefetch_count=1, channel_separe=False, callback_is_asyncio=False):
        super().__init__(module_messages, ressources, callback, prefetch_count, channel_separe, callback_is_asyncio)


class MessagePending:

    def __init__(self, content: bytes, routing_key: str, exchanges: list, reply_to=None, correlation_id=None):
        self.content = content
        self.routing_key = routing_key
        self.reply_to = reply_to
        self.correlation_id = correlation_id
        self.exchanges = exchanges


class MessageProducer:

    def __init__(self, module_messages: MessagesModule, reply_res: Optional[RessourcesConsommation] = None):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self._module_messages = module_messages
        self._reply_res = reply_res

        self._message_number = 0
        self.__deliveries = list()  # Q d'emission de message, permet d'emettre via thread IO-LOOP

        self.__event_message: Optional[Event] = None

        self.__actif = False

    def emettre(self, message: Union[str, bytes], routing_key: str, exchanges: Union[str, list],
                correlation_id: str = None, reply_to: str = None):

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

        # Notifier thread en await
        self.__event_message.set()

    async def run_async(self):
        self.__actif = True
        self.__event_message = Event()

        try:
            while self.__actif:
                self.__logger.debug("Wake up producer")

                while len(self.__deliveries) > 0:
                    message = self.__deliveries.pop(0)
                    self.__logger.debug("producer : send message %s" % message)
                    await self.send(message)

                # Attendre prochains messages
                self.__logger.debug("producer : attente prochain message")
                await self.__event_message.wait()
                self.__event_message.clear()  # Reset flag
        except:
            self.__logger.exception("Erreur traitement, producer arrete")

        self.__actif = False

    async def send(self, message):
        self.__logger.warning("NOT IMPLEMENTED - Emettre message %s", message)


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
