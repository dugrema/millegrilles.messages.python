import asyncio
import logging
from asyncio import TaskGroup

import pika
import ssl

from typing import Awaitable, Optional, Callable

from pika.adapters.asyncio_connection import AsyncioConnection
from pika.channel import Channel
from pika.exceptions import ProbableAuthenticationError

from millegrilles_messages.bus.BusContext import MilleGrillesBusContext, StopListener, ForceTerminateExecution

CONST_CONNECTION_ATTEMTPS = 5
CONST_RETRY_DELAY = 5.0
CONST_HEARTBEAT = 30
CONST_BLOCKED_CONNECTION_TIMEOUT = 20

LOGGER = logging.getLogger(__name__)


class MilleGrillesPikaBusConnection(StopListener):

    def __init__(self, context: MilleGrillesBusContext,
                 on_connect: Callable[[], Awaitable[None]], on_disconnect: Callable[[], Awaitable[None]]):
        super().__init__()
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__context = context
        self.__on_connect_callback = on_connect
        self.__on_disconnect_callback = on_disconnect

        self._connection: Optional[AsyncioConnection] = None
        self._closing = False

        self.__event_connection_stopping = asyncio.Event()
        self.__loop = asyncio.get_event_loop()
        self.__access_just_created = False

        context.register_stop_listener(self)

    @property
    def connected(self):
        return self._connection and self._connection.is_open

    async def stop(self):
        self.__event_connection_stopping.set()

    async def run(self):
        async with TaskGroup() as group:
            group.create_task(self.run_ioloop())
            group.create_task(self.maintenance_thread())

        if self.__context.stopping is False:
            self.__logger.error("PikaBusConnection thread exited abruptly, stopping application")
            self.__context.stop()
            raise ForceTerminateExecution()

        self.__logger.info("MilleGrillesPikaBusConnection thread closed")

    async def maintenance_thread(self):
        while self.__context.stopping is False:
            await self.__context.wait(duration=30)

    async def connect(self):
        hostname = self.__context.configuration.mq_hostname
        port = self.__context.configuration.mq_port

        # Extraire IDMG du certificat. C'est le virtual host RabbitMQ.
        enveloppe_cert = self.__context.signing_key.enveloppe
        idmg = enveloppe_cert.idmg

        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        tls_context.verify_mode = ssl.CERT_REQUIRED
        tls_context.load_verify_locations(self.__context.configuration.ca_path)
        tls_context.load_cert_chain(self.__context.configuration.cert_path, self.__context.configuration.key_path)
        ssl_options = pika.SSLOptions(tls_context, hostname)

        parameters = pika.ConnectionParameters(
            host=hostname,
            port=port,
            virtual_host=idmg,
            credentials=pika.credentials.ExternalCredentials(),
            ssl_options=ssl_options,
            connection_attempts=CONST_CONNECTION_ATTEMTPS,
            retry_delay=CONST_RETRY_DELAY,
            heartbeat=CONST_HEARTBEAT,
            blocked_connection_timeout=CONST_BLOCKED_CONNECTION_TIMEOUT)

        event = asyncio.Event()
        result = dict()
        def on_connection_open(_unused_connection: AsyncioConnection):
            self.__loop.call_soon_threadsafe(event.set)

        def on_connection_open_error(_unused_connection: AsyncioConnection, err: BaseException):
            result['err'] = err
            self.__loop.call_soon_threadsafe(event.set)

        self._connection = AsyncioConnection(
            parameters,
            custom_ioloop=self.__loop,
            on_open_callback=on_connection_open,
            on_open_error_callback=on_connection_open_error,
            on_close_callback=self.on_connection_closed)

        await event.wait()
        exception = result.get('err')
        if exception:
            if isinstance(exception, ProbableAuthenticationError):
                await self.create_midleware_access()  # On success, raises MiddlewareAccessCreatedException
            raise exception

        self.__logger.debug("Connection adapter : %s", self._connection)

    def close_connection(self):
        if self._connection.is_closing or self._connection.is_closed:
            self.__logger.info('Connection is closing or already closed')
        else:
            self.__logger.info('Closing connection')
            self._connection.close()

    def on_connection_closed(self, _unused_connection: AsyncioConnection, reason: BaseException):
        """This method is invoked by pika when the connection to RabbitMQ is
        closed unexpectedly. Since it is unexpected, we will reconnect to
        RabbitMQ if it disconnects.

        :param pika.adapters.asyncio_connection.AsyncioConnection _unused_connection: The closed connection obj
        :param Exception reason: exception representing reason for loss of
            connection.
        """
        self.__loop.call_soon_threadsafe(self.__event_connection_stopping.set)

    async def open_channel(self) -> Channel:
        """Open a new channel with RabbitMQ by issuing the Channel.Open RPC
        command. When RabbitMQ responds that the channel is open, the
        on_channel_open callback will be invoked by pika.

        """
        self.__logger.info('Creating a new channel')
        channel_dict = {}
        event = asyncio.Event()

        def callback(new_channel: Channel):
            channel_dict['channel'] = new_channel
            self.__loop.call_soon_threadsafe(event.set)

        self._connection.channel(on_open_callback=callback)
        await asyncio.wait_for(event.wait(), 10)
        return channel_dict.get('channel')

    async def run_ioloop(self):
        """Run the example consumer by connecting to RabbitMQ and then
        starting the IOLoop to block and allow the AsyncioConnection to operate.

        """
        while self.__context.stopping is False:
            self.__logger.info("run_ioloop Connecting to MQ bus")

            try:
                await self.connect()
            except MiddlewareAccessCreatedException:
                self.__logger.info("Middleware access was just created - retry")
                if self.__access_just_created is True:
                    raise Exception('Error creating middleware access, looping')
                self.__access_just_created = True
                await self.__context.wait(2)
                continue

            await self.__on_connect_callback()

            await self.__event_connection_stopping.wait()
            await self.__on_disconnect_callback()

            self.__event_connection_stopping.clear()  # Reset flag for reconnect if applicable
            self.__logger.debug("run_ioloop Disconnecting from MQ bus")

            if self._connection and self._connection.is_open:
                self._connection.close()

            self.__logger.debug("run_ioloop Disconnected from MQ bus")

            # Wait for retry if applicable (using context event)
            await self.__context.wait(CONST_RETRY_DELAY)

    async def create_midleware_access(self):
        self.__logger.info("Creating middleware access using nginx")
        configuration = self.__context.configuration
        result = await asyncio.to_thread(
            _create_middleware_access, configuration.mq_hostname, configuration.ca_path, configuration.cert_path,
            configuration.key_path)
        if result is True:
            raise MiddlewareAccessCreatedException()


class MiddlewareAccessCreatedException(Exception):
    pass


def _create_middleware_access(mq_host: str, ca_path: str, cert_path: str, key_path: str):
    """
    Creer un compte sur MQ via https (midcompte).
    :return:
    """
    LOGGER.info("Creating MQ account using host %s" % mq_host)

    # Le monitor peut etre trouve via quelques hostnames :
    #  nginx : de l'interne, est le proxy web qui est mappe vers le monitor
    #  mq_host : de l'exterieur, est le serveur mq qui est sur le meme swarm docker_obsolete que nginx
    hosts = ['nginx', mq_host, 'localhost']
    port = 444
    path = 'administration/ajouterCompte'

    with open(cert_path, 'r') as fichier:
        chaine_cert = {'certificat': fichier.read()}

    cle_cert = (cert_path, key_path)
    LOGGER.debug("Creation compte MQ avec fichiers %s" % str(cle_cert))
    try:
        import requests
        for host in hosts:
            path_complet = 'https://%s:%d/%s' % (host, port, path)
            try:
                LOGGER.debug("Creation compte avec path %s" % path_complet)
                reponse = requests.post(path_complet, json=chaine_cert, cert=cle_cert, verify=ca_path)
                if reponse.status_code in [200, 201]:
                    return True
                else:
                    LOGGER.error("Erreur creation compte MQ via https, code : %d", reponse.status_code)
            except requests.exceptions.SSLError as e:
                LOGGER.exception("Erreur connexion https pour compte MQ")
            except requests.exceptions.ConnectionError:
                # Erreur connexion au serveur, tenter le prochain host
                LOGGER.info("Echec creation compte MQ avec %s" % path_complet)
    except ImportError:
        LOGGER.warning("requests non disponible, on ne peut pas tenter d'ajouter le compte MQ")

    return False
