"""
DAO pour messages.
"""
import asyncio
import datetime
import json
import logging
import resource

from threading import Event as EventThreading
from typing import Optional, Union
from uuid import uuid4

from asyncio import Event
from asyncio.exceptions import TimeoutError

from millegrilles_messages.messages import Constantes
from millegrilles_messages.messages.CleCertificat import CleCertificat
from millegrilles_messages.messages.EnveloppeCertificat import EnveloppeCertificat
from millegrilles_messages.messages.FormatteurMessages import FormatteurMessageMilleGrilles, SignateurTransactionSimple
from millegrilles_messages.messages.ValidateurMessage import ValidateurMessage
from millegrilles_messages.messages.ValidateurCertificats import ValidateurCertificatRedis


ATTENTE_MESSAGE_DUREE = 15  # Attente par defaut de 15 secondes


class RessourcesConsommation:

    def __init__(self, callback, nom_queue: Optional[str] = None,
                 channel_separe=False, est_asyncio=False, prefetch_count=1, auto_delete=False, exclusive=False, durable=False, actif=True):
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
        self.actif = actif
        self.nb_max_attente = 10

    def ajouter_rk(self, exchange: str, rk: str):
        if self.rk is None:
            self.rk = list()
        self.rk.append(RessourcesRoutingKey(exchange, rk))

    def set_ttl(self, ttl: int):
        if self.arguments is None:
            self.arguments = dict()
        self.arguments['x-message-ttl'] = ttl

    def start(self):
        if self.actif is False:
            raise NotImplementedError('todo')

    def stop(self):
        if self._actif:
            raise NotImplementedError('todo')


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


class ExchangeConfiguration:

    def __init__(self, nom, type_exchange):
        self.nom = nom
        self.type_exchange = type_exchange

    def __str__(self):
        return 'ExchangeConfiguration %s' % self.nom

    def __hash__(self):
        return hash(self.nom)

    def __eq__(self, other):
        return other.nom == self.nom


class MessagesModule:

    def __init__(self):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self._consumers = list()
        self._reply_consumer = None
        self._producer = None
        self._exchanges: Optional[list] = None

        self.__event_pret = EventThreading()

        self.__event_attente: Optional[Event] = None

        self._validateur_certificats: Optional[ValidateurCertificatRedis] = None
        self._validateur_messages: Optional[ValidateurMessage] = None

        self.__event_loop = None

    async def __entretien_task(self):
        self.__event_attente = Event()

        while not self.__event_attente.is_set():
            await self.entretien(self.__event_attente)

            try:
                await asyncio.wait_for(self.__event_attente.wait(), 30)
            except TimeoutError:
                pass

    async def entretien(self, event_stop: asyncio.Event):
        est_connecte = self.est_connecte()
        self.__logger.debug("entretien Etat connexion MQ : Connecte = %s" % est_connecte)

        if est_connecte is False:
            self.__logger.debug("entretien Reconnecter MQ")
            await self._connect()

    async def run_async(self):
        self.__event_loop = asyncio.get_event_loop()

        # Creer tasks pour producers, consumers et entretien
        tasks = [
            asyncio.create_task(self.__entretien_task()),
            asyncio.create_task(self._producer.run_async()),
        ]

        for consumer in self._consumers:
            tasks.append(asyncio.create_task(consumer.run_async()))

        # Execution de la loop avec toutes les tasks
        await asyncio.gather(*tasks)
        # pending = set(tasks)
        # while len(pending) > 0:
        #     done, pending = await asyncio.tasks.wait(pending, return_when=asyncio.tasks.FIRST_COMPLETED)
        #     self.__logger.info("run_async %d Consumers done, %d remaining" % (len(done), len(pending)))

        self.__logger.info("run_async thread completee")

    def est_connecte(self) -> bool:
        raise NotImplementedError('Not implemented')

    async def _connect(self):
        raise NotImplementedError('Not implemented')

    async def _close(self):
        pass
        # await self._reply_consumer.fermer()
        # for consumer in self._consumers:
        #     consumer.fermer()
        # raise NotImplementedError('Not implemented')

    async def fermer(self):
        await self._reply_consumer.fermer()
        for consumer in self._consumers:
            await consumer.fermer()

        await self._close()

    def ajouter_consumer(self, consumer, reply=False):  # Type MessageConsumer
        self._consumers.append(consumer)
        if reply is True:
            self._reply_consumer = consumer

    async def preparer_ressources(self, env_configuration: Optional[dict] = None,
                                  reply_res: Optional[RessourcesConsommation] = None,
                                  consumers: Optional[list] = None,
                                  exchanges: Optional[list] = None):
        raise NotImplementedError('Not implemented')

    def get_producer(self):
        return self._producer

    def get_consumers(self):
        return self._consumers

    def get_reply_consumer(self):
        return self._reply_consumer

    def get_validateur_messages(self):
        return self._validateur_messages

    def get_validateur_certificats(self):
        return self._validateur_certificats

    async def attendre_pret(self, max_delai=20):
        event_producer = self._producer.producer_pret()
        # event_producer.wait(max_delai)
        await asyncio.wait_for(event_producer.wait(), max_delai)

        if event_producer.is_set() is False:
            raise Exception("Timeout attente producer")

        for consumer in self._consumers:
            event = consumer.consumer_pret()
            # event.wait(max_delai)
            await asyncio.wait_for(event.wait(), max_delai)

            if event.is_set() is False:
                raise Exception("Timeout attente consumer")

    def get_event_loop(self):
        return self.__event_loop


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
        self.__kind: Optional[int] = None
        self.__estampille: Optional[int] = None
        self.__routage: Optional[dict] = None
        self.__parsed: Optional[dict] = None
        self.__contenu: Optional[str] = None
        self.__certificat_pem: Optional[list] = None
        self.__pubkey: Optional[str] = None
        self.original: Optional[str] = None
        self.certificat: Optional[EnveloppeCertificat] = None
        self.est_valide = False

    @property
    def parsed(self):
        return self.__parsed

    @parsed.setter
    def parsed(self, val: dict):
        self.original = val
        self.__pubkey = val['pubkey']
        self.__kind = val['kind']
        self.__estampille = val['estampille']
        self.__routage = val.get('routage')
        self.__contenu = val['contenu']
        self.__certificat_pem = val.get('certificat')
        if self.__kind not in [6, 8]:
            # Extraire le contenu et donner acces a l'original parsed (val) via __original
            parsed_contenu = json.loads(val['contenu'])
            parsed_contenu['__original'] = val
            self.__parsed = parsed_contenu

    @property
    def pubkey(self) -> str:
        return self.__pubkey

    @property
    def kind(self) -> int:
        return self.__kind

    @property
    def estampille(self) -> int:
        return self.__estampille

    @property
    def routage(self) -> Optional[dict]:
        return self.__routage

    @property
    def certificat_pem(self) -> Optional[list]:
        return self.__certificat_pem

    def __str__(self):
        return 'tag:%d' % self.delivery_tag


class MessagePending:

    def __init__(self, content: bytes, routing_key: str, exchanges: list, reply_to=None, correlation_id=None, headers: Optional[dict] = None):
        self.content = content
        self.routing_key = routing_key
        self.reply_to = reply_to
        self.correlation_id = correlation_id
        self.exchanges = exchanges
        self.headers = headers


class CorrelationReponse:

    def __init__(self, correlation_id: str):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.correlation_id = correlation_id

        self.__creation = datetime.datetime.utcnow()
        self.__duree_attente = ATTENTE_MESSAGE_DUREE

        self.consumer = None  # MessageConsumer
        self.__event_attente = Event()
        self.__reponse: Optional[MessageWrapper] = None
        self.__reponse_consommee = False
        self.__reponse_annulee = False

    async def attendre_reponse(self, timeout=ATTENTE_MESSAGE_DUREE) -> MessageWrapper:
        self.__duree_attente = timeout
        try:
            await asyncio.wait_for(self.__event_attente.wait(), timeout)
            if self.__reponse_annulee:
                raise Exception('Annulee')
        #except TimeoutError:
        finally:
            # Effacer la correlation immediatement
            try:
                await self.consumer.retirer_correlation(self.correlation_id)
            except AttributeError:
                pass  # OK - le consumer n'a jamais ete associe (e.g. correlation doublon)

        self.__reponse_consommee = True
        return self.__reponse

    async def recevoir_reponse(self, message: MessageWrapper):
        self.__reponse = message
        self.__event_attente.set()

    def est_expire(self):
        duree_message = datetime.timedelta(seconds=self.__duree_attente)
        if self.__reponse_consommee:
            duree_message = duree_message * 3  # On donne un delai supplementaire si la reponse n'est pas consommee

        date_expiration = datetime.datetime.utcnow() - duree_message

        return self.__creation < date_expiration

    async def annulee(self):
        if self.__reponse_consommee is False:
            self.__logger.debug("Correlation reponse %s annulee par le consumer" % self.correlation_id)
            self.__reponse_annulee = True
            self.__event_attente.set()


class MessageProducer:

    def __init__(self, module_messages: MessagesModule):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self._module_messages = module_messages

        self._reply_consumer = None
        self._message_number = 0
        self.__deliveries = list()  # Q d'emission de message, permet d'emettre via thread IO-LOOP

        self.__loop = None
        self.__event_message: Optional[Event] = None
        self._event_q_prete = EventThreading()
        self.__NB_MESSAGE_MAX = 10

        self.__actif = False
        # self._producer_pret = EventThreading()
        self._producer_pret = Event()

    async def emettre(self, message: Union[str, bytes], routing_key: str,
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
            if self._reply_consumer is not None:
                reply_to = self._reply_consumer.get_ressources().q

        pending = MessagePending(message, routing_key, exchanges, reply_to, correlation_id)
        self.__deliveries.append(pending)

        # Notifier thread en await
        # self.__loop.call_soon_threadsafe(self.__event_message.set)
        self.__event_message.set()

    async def emettre_attendre(self, message: Union[str, bytes], routing_key: str,
                               exchange: Optional[str] = None, correlation_id: str = None,
                               reply_to: str = None, timeout=ATTENTE_MESSAGE_DUREE):
        if reply_to is None:
            reply_to = await self.get_reply_q()

        # Bug - si un message avec meme contenu est emis plusieurs fois durant la meme seconde,
        #       la correlation echoue (reponses des duplications sont perdues).
        #       Ajouter le compteur de messages pour rendre unique pour ce producer.
        if correlation_id is None:
            # correlation_id = str(uuid4())
            correlation_id = '%d/%s' % (self._message_number, str(uuid4()))
        else:
            correlation_id = '%d/%s' % (self._message_number, correlation_id)

        self._message_number += 1  # Incrementer compteur

        # Conserver reference a la correlation
        correlation_reponse = CorrelationReponse(correlation_id)
        semaphore = self._module_messages.get_reply_consumer().semaphore_correlations
        # Utiliser semaphore pour limiter le nombre de requetes en attente simultanement
        async with semaphore:
            await self._module_messages.get_reply_consumer().ajouter_attendre_reponse(correlation_reponse)

            # Emettre le message
            await self.emettre(message, routing_key, exchange, correlation_id, reply_to)

            # Attendre la reponse. raises TimeoutError
            reponse = await correlation_reponse.attendre_reponse(timeout)

        return reponse

    async def run_async(self):
        self.__logger.info("Demarrage run_async producer")
        self.__loop = asyncio.get_event_loop()
        self.__actif = True
        self.__event_message = Event()

        try:
            while self.__actif:
                while len(self.__deliveries) > 0:
                    message = self.__deliveries.pop(0)
                    self.__logger.debug("producer : send message")
                    await self.send(message)

                self._event_q_prete.set()  # Debloque reception de messages

                # Attendre prochains messages
                await self.__event_message.wait()
                self.__logger.debug("Wake up producer")

                self.__event_message.clear()  # Reset flag
        except asyncio.CancelledError:
            self.__logger.debug("Arret producer (cancelled)")
        except:
            self.__logger.exception("Erreur traitement, producer arrete")

        self.__actif = False

    async def send(self, message: MessagePending):
        self.__logger.warning("NOT IMPLEMENTED - Emettre message")

    def set_reply_consumer(self, consumer):
        self._reply_consumer = consumer

    async def get_reply_q(self):
        if self._reply_consumer is not None:
            if not self._reply_consumer.consumer_pret().is_set():
                await asyncio.wait_for(self._reply_consumer.consumer_pret().wait(), 20)
            return self._reply_consumer.get_ressources().q

    def producer_pret(self) -> Event:
        return self._producer_pret


class MessageProducerFormatteur(MessageProducer):
    """
    Produceur qui formatte le message a emettre.
    """

    def __init__(self, module_messages: MessagesModule, clecert: CleCertificat):
        super().__init__(module_messages)
        self.__formatteur_messages: FormatteurMessageMilleGrilles = \
            MessageProducerFormatteur.__preparer_formatteur(clecert)

    @staticmethod
    def __preparer_formatteur(clecert: CleCertificat) -> FormatteurMessageMilleGrilles:
        idmg = clecert.enveloppe.idmg
        signateur = SignateurTransactionSimple(clecert)
        formatteur = FormatteurMessageMilleGrilles(idmg, signateur)
        return formatteur

    async def signer(self, message: dict, kind: Constantes.KIND_DOCUMENT, domaine: Optional[str] = None, action: Optional[str] = None, partition: Optional[str] = None, version=1) -> dict:
        return self.__formatteur_messages.signer_message(kind, message, domaine, action=action, partition=partition)

    async def emettre_evenement(self, evenement: dict, domaine: str, action: str,
                                partition: Optional[str] = None, exchanges: Union[str, list] = None, version=1,
                                reply_to=None, noformat=False):

        if noformat is False:
            message, uuid_message = self.__formatteur_messages.signer_message(
                Constantes.KIND_EVENEMENT, evenement, domaine, action=action, partition=partition)
        else:
            message = evenement
            uuid_message = evenement['id']

        correlation_id = str(uuid_message)

        rk = ['evenement', domaine]
        if partition is not None:
            rk.append(partition)
        rk.append(action)

        message_bytes = json.dumps(message)

        await self.emettre(message_bytes, '.'.join(rk), exchanges, correlation_id, reply_to)

    async def executer_commande(self, commande: dict, domaine: str, action: str, exchange: str,
                                partition: Optional[str] = None, version=1,
                                reply_to=None, nowait=False, noformat=False, timeout=15,
                                attachements: Optional[dict] = None, kind=Constantes.KIND_COMMANDE) -> Optional[MessageWrapper]:

        if noformat is True:
            message = commande
            uuid_message = commande['id']
        else:
            # Signer le message
            message, uuid_message = self.__formatteur_messages.signer_message(
                kind, commande, domaine, action=action, partition=partition)

        if attachements is not None:
            message['attachements'] = attachements

        correlation_id = str(uuid_message)

        rk = ['commande', domaine]
        if partition is not None:
            rk.append(partition)
        rk.append(action)

        message_bytes = json.dumps(message)

        if nowait is True:
            await self.emettre(message_bytes, '.'.join(rk), exchanges=exchange, correlation_id=correlation_id)
        else:
            reponse = await self.emettre_attendre(message_bytes, '.'.join(rk),
                                                  exchange=exchange, correlation_id=correlation_id, reply_to=reply_to,
                                                  timeout=timeout)
            return reponse

    async def executer_requete(self, requete: dict, domaine: str, action: str, exchange: str,
                               partition: Optional[str] = None, version=1,
                               reply_to=None, timeout=ATTENTE_MESSAGE_DUREE, noformat=False,
                               attachements: Optional[dict] = None) -> MessageWrapper:

        if noformat is True:
            message = requete
            uuid_message = requete['id']
        else:
            message, uuid_message = self.__formatteur_messages.signer_message(
                Constantes.KIND_REQUETE, requete, domaine, action=action, partition=partition)

        if attachements is not None:
            message['attachements'] = attachements

        correlation_id = str(uuid_message)

        rk = ['requete', domaine]
        if partition is not None:
            rk.append(partition)
        rk.append(action)

        message_bytes = json.dumps(message)

        reponse = await self.emettre_attendre(message_bytes, '.'.join(rk),
                                              exchange=exchange, correlation_id=correlation_id,
                                              reply_to=reply_to, timeout=timeout)
        return reponse

    async def soumettre_transaction(self, transaction: dict, domaine: str, action: str, exchange: str,
                                    partition: Optional[str] = None, version=1,
                                    reply_to=None, nowait=False,
                                    attachements: Optional[dict] = None):

        message, uuid_message = self.__formatteur_messages.signer_message(
            Constantes.KIND_TRANSACTION, transaction, domaine, version, action=action, partition=partition)

        if attachements is not None:
            message['attachements'] = attachements

        correlation_id = str(uuid_message)

        rk = ['transaction', domaine]
        if partition is not None:
            rk.append(partition)
        rk.append(action)

        message_bytes = json.dumps(message)

        if nowait is not True:
            reponse = await self.emettre_attendre(message_bytes, '.'.join(rk),
                                                  exchange=exchange, correlation_id=correlation_id, reply_to=reply_to)
            return reponse

    async def repondre(self, reponse: dict, reply_to, correlation_id, version=1, noformat=False, attachements: Optional[dict] = None):
        if noformat is not True:
            message, uuid_message = self.__formatteur_messages.signer_message(Constantes.KIND_REPONSE, reponse)
        else:
            message = reponse

        if attachements is not None:
            message['attachements'] = attachements

        message_bytes = json.dumps(message)
        routing_key = reply_to
        await self.emettre(message_bytes, routing_key, correlation_id=correlation_id, reply_to=reply_to)


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
        # self._event_correlation_recu: Optional[Event] = None
        self._stop_event: Optional[Event] = None

        # Q de messages en memoire
        self._messages: Optional[asyncio.Queue] = None

        self._consumer_pret = Event()

        # [correlation_id] = CorrelationReponse()
        self._correlation_reponse = dict()
        # Nombre maximal de reponses en attente
        self._semaphore_correlations = asyncio.BoundedSemaphore(value=ressources.nb_max_attente)

        self._erreur_channel = False

    @property
    def semaphore_correlations(self) -> asyncio.BoundedSemaphore:
        return self._semaphore_correlations

    @property
    def erreur_channel(self) -> bool:
        return self._erreur_channel

    async def fermer(self):
        # Liberer boucles
        self._stop_event.set()
        self._event_consumer.clear()
        self._event_message.set()

    async def run_async(self):
        self.__logger.info("Demarrage consumer %s" % self._ressources.q)

        # Setup asyncio
        self._messages = asyncio.Queue(maxsize=self._ressources.prefetch_count + 2)
        self.__loop = asyncio.get_event_loop()
        self._event_channel = Event()
        self._event_consumer = Event()
        self._event_message = Event()
        self._stop_event = Event()
        # self._event_correlation_recu = Event()

        # # Attente ressources
        # await self._event_channel.wait()
        # await self._event_consumer.wait()

        self.__logger.info("Consumer actif")
        tasks = [
            asyncio.create_task(self.__traiter_messages()),
            asyncio.create_task(self.__entretien())
        ]

        # Execution de la loop avec toutes les tasks
        await asyncio.tasks.wait(tasks, return_when=asyncio.tasks.FIRST_COMPLETED)

        self._consumer_pret.clear()
        self.__logger.info("Arret consumer %s" % self._ressources.q)

    async def __traiter_messages(self):
        pending = {asyncio.create_task(self._stop_event.wait())}
        while self._stop_event.is_set() is False:
            pending.add(asyncio.create_task(self._messages.get()))
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            if self._stop_event.is_set():
                break  # Done

            for d in done:
                if d.exception():
                    self.__logger.error("__traiter_messages Erreur %s" % d.exception())
                else:
                    try:
                        message = d.result()
                        await self.__traiter_message(message)
                    except:
                        self.__logger.exception("__traiter_messages Erreur traitement message")

        for p in pending:
            p.cancel()
            try:
                await p
            except asyncio.CancelledError:
                pass  # OK
            except AttributeError:
                pass  # Pas une task

    async def __entretien(self):
        while self._stop_event.is_set() is False:
            if self._correlation_reponse is not None:
                correlations = list(self._correlation_reponse.values())
                for corr in correlations:
                    if corr.est_expire():
                        correlation_id = corr.correlation_id
                        del self._correlation_reponse[correlation_id]
                        await corr.annulee()

            try:
                await asyncio.wait_for(self._stop_event.wait(), 30)
            except TimeoutError:
                pass

    def recevoir_message(self, message: MessageWrapper):
        self.__logger.debug("recevoir_message")

        # Utiliser le put_nowait - la Q interne ne devrait jamais avoir plus d'un message en traitement
        try:
            self._messages.put_nowait(message)
        except asyncio.QueueFull:
            self.__logger.exception("recevoir_message FATAL Queue interne de traitement pleine, message perdu %s/%s %s" % (
                message.correlation_id, message.routing_key, message.parsed))

    async def __traiter_message(self, message: MessageWrapper):
        # Clear flag, permet de s'assurer de bloquer sur un message en attente
        try:
            self.__logger.debug("Message a traiter : %s" % message.delivery_tag)
            await self._traiter_message(message)
        finally:
            # Debloquer Q pour le prochain message
            self.__logger.debug("Message traite, ACK %s" % message.delivery_tag)
            self.ack_message(message)

    async def _traiter_message(self, message: MessageWrapper):
        # Verifier si on intercepte une reponse
        if self._correlation_reponse is not None:
            correlation_id = message.correlation_id
            if correlation_id is not None:
                try:
                    corr_reponse = self._correlation_reponse[correlation_id]
                    del self._correlation_reponse[correlation_id]  # Cleanup
                    # if not self._event_correlation_recu.is_set():
                    #     self._event_correlation_recu.set()
                    await corr_reponse.recevoir_reponse(message)
                    return  # Termine
                except KeyError:
                    pass

        # Effectuer le traitement
        await self._ressources.callback(message, self._module_messages)

    def repondre_certificat(self, message: MessageWrapper):
        pems = ['']
        fingerprint = ''
        reponse = {'chaine_pem': pems, 'fingerprint': fingerprint}
        producer = self._module_messages.get_producer()
        producer.repondre(reponse, message.reply_to, message.correlation_id)
        self.ack_message(message)

    def get_ressources(self):
        return self._ressources

    def ack_message(self, message: MessageWrapper):
        raise NotImplementedError('Not implemented')

    def consumer_pret(self) -> Event:
        return self._consumer_pret

    async def ajouter_attendre_reponse(self, correlation_reponse: CorrelationReponse):
        try:
            correlation_existante = self._correlation_reponse[correlation_reponse.correlation_id]
            self.__logger.warning("Annuler doublon du message avec correlation %s" % correlation_reponse.correlation_id)
            await correlation_reponse.annulee()
        except KeyError:
            # Aucun doublon pour meme correlation
            correlation_reponse.consumer = self
            self._correlation_reponse[correlation_reponse.correlation_id] = correlation_reponse

    async def retirer_correlation(self, correlation_id: str):
        try:
            correlation = self._correlation_reponse[correlation_id]
            del self._correlation_reponse[correlation_id]
            # if not self._event_correlation_recu.is_set():
            #     self._event_correlation_recu.set()
            await correlation.annulee()
        except KeyError:
            pass


class MessageConsumerVerificateur(MessageConsumer):

    def __init__(self, module_messages: MessagesModule, ressources: RessourcesConsommation):
        super().__init__(module_messages, ressources)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    async def _traiter_message(self, message: MessageWrapper):
        parsed = json.loads(message.contenu)
        message.parsed = parsed

        # parsed['corrompu'] = True

        # Verifier le message (certificat, signature)
        try:
            enveloppe_certificat = await self._module_messages.get_validateur_messages().verifier(parsed)
            message.certificat = enveloppe_certificat
            message.est_valide = True
            # Message OK
            await super()._traiter_message(message)
        except:
            # Message invalide
            self.__logger.exception("Erreur traitement message %s" % message.routing_key)
