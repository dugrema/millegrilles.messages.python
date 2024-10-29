import asyncio
import logging
import pika
import ssl

from typing import Awaitable, Optional, Callable

from pika.adapters.asyncio_connection import AsyncioConnection
from pika.channel import Channel

from millegrilles_messages.bus.BusContext import MilleGrillesBusContext, StopListener

CONST_CONNECTION_ATTEMTPS = 5
CONST_RETRY_DELAY = 5.0
CONST_HEARTBEAT = 30
CONST_BLOCKED_CONNECTION_TIMEOUT = 20


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
        self.__loop: Optional[asyncio.EventLoop] = None

        context.register_stop_listener(self)

    @property
    def connected(self):
        return self._connection and self._connection.is_open

    async def stop(self):
        self.__event_connection_stopping.set()

    async def run(self):
        self.__loop = asyncio.get_event_loop()
        done, pending = await asyncio.wait([
            asyncio.create_task(self.run_ioloop()),
            asyncio.create_task(self.maintenance_thread()),
        ], return_when=asyncio.FIRST_COMPLETED)
        if self.__context.stopping is not True:
            self.__logger.error("Thread quit unexpectedly: %s" % done)
            self.__context.stop()
        if len(pending) > 0:
            await asyncio.gather(*pending)

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
        loop = asyncio.get_event_loop()
        result = dict()
        def on_connection_open(_unused_connection: AsyncioConnection):
            loop.call_soon(event.set)

        def on_connection_open_error(_unused_connection: AsyncioConnection, err: BaseException):
            result['err'] = err
            loop.call_soon(event.set)

        self._connection = AsyncioConnection(
            parameters,
            custom_ioloop=loop,
            on_open_callback=on_connection_open,
            on_open_error_callback=on_connection_open_error,
            on_close_callback=self.on_connection_closed)

        await event.wait()
        if result.get('err'):
            raise result['err']

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
        self.__loop.call_soon(self.__event_connection_stopping.set())

    async def open_channel(self) -> Channel:
        """Open a new channel with RabbitMQ by issuing the Channel.Open RPC
        command. When RabbitMQ responds that the channel is open, the
        on_channel_open callback will be invoked by pika.

        """
        self.__logger.info('Creating a new channel')
        channel_dict = {}
        event = asyncio.Event()

        loop = asyncio.get_event_loop()
        def callback(new_channel: Channel):
            channel_dict['channel'] = new_channel
            loop.call_soon(event.set)

        self._connection.channel(on_open_callback=callback)
        await asyncio.wait_for(event.wait(), 10)
        return channel_dict.get('channel')

    async def run_ioloop(self):
        """Run the example consumer by connecting to RabbitMQ and then
        starting the IOLoop to block and allow the AsyncioConnection to operate.

        """
        while self.__context.stopping is False:
            self.__logger.info("run_ioloop Connecting to MQ bus")

            await self.connect()
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

    def __stop_connection(self):
        """ Shutdown the connection to RabbitMQ """
        if not self._closing:
            self._closing = True
            self.__logger.debug('__stop_connection Stopping')
            self.__logger.debug('__stop_connection Stopped')
