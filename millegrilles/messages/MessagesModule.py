import logging
import asyncio

from typing import Optional, Union

from asyncio import Event


class MessagesModule:

    def __init__(self):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__consumers = list()
        self._producer = None

    async def entretien(self):
        if self.est_connecte() is True:
            self.__logger.debug("Verifier etat connexion MQ")

        if self.est_connecte() is False:
            self.__logger.debug("Connecter MQ")
            await self._connect()

    async def run_async(self):

        # Creer tasks pour producers, consumers et entretien
        tasks = [
            asyncio.create_task(self.entretien()),
            asyncio.create_task(self._producer.run()),
        ]

        for consumer in self.__consumers:
            tasks.append(consumer.run_async())

        # Execution de la loop avec toutes les tasks
        await asyncio.tasks.wait(tasks, return_when=asyncio.tasks.FIRST_EXCEPTION)

    def est_connecte(self) -> bool:
        raise NotImplementedError('Not implemented')

    async def _connect(self):
        raise NotImplementedError('Not implemented')

    async def _close(self):
        raise NotImplementedError('Not implemented')

    def creer_consumer(self):
        pass

    def preparer_ressources(self):
        raise NotImplementedError('Not implemented')


class RessourcesConsommation:

    def __init__(self, nom_queue: Optional[str], routing_keys: Optional[list] = None):
        """
        Pour creer une reply-Q, fournir routing_keys et laisser nom_queue vide.
        Pour configurer une nouvelle Q, inlcure une liste de routing_keys avec le nom de la Q.
        :param nom_queue:
        :param routing_keys:
        """

        if nom_queue is None and routing_keys is None:
            raise ValueError('Il faut fournir au moins un nom de queue ou une liste de routing_keys')

        self.q = nom_queue  # Param est vide, le nom de la Q va etre conserve lors de la creation de la reply-Q
        self.rk = routing_keys
        self.est_reply_q = self.q is None


class MessageConsumer:
    """
    Consumer pour une Q.
    """

    def __init__(self, module_messages: MessagesModule, ressources: RessourcesConsommation,
                 prefetch_count=1, channel_separe=False):
        self._module_messages = module_messages
        self._ressources = ressources
        self._channel_separe = channel_separe

        self._consuming = False
        self._prefetch_count = prefetch_count

    def start_consuming(self):
        if self._consuming is True:
            return  # Rien a faire

    def stop_consuming(self):
        if self._consuming is False:
            return  # Rien a faire

        self._consuming = False

    async def entretien(self):
        pass


class MessageConsumerVerificateur(MessageConsumer):

    def __init__(self, module_messages: MessagesModule, ressources: RessourcesConsommation,
                 prefetch_count=1, channel_separe=False):
        super().__init__(module_messages, ressources,prefetch_count, channel_separe)


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

        self.__event_message: Event = None

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

    async def run(self):
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
