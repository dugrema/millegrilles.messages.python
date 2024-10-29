import asyncio
import logging
import pika
import ssl

from typing import Optional

from pika.adapters.asyncio_connection import AsyncioConnection
from pika.channel import Channel

from millegrilles_messages.bus.BusContext import MilleGrillesBusContext, StopListener

CONST_CONNECTION_ATTEMTPS = 5
CONST_RETRY_DELAY = 5.0
CONST_HEARTBEAT = 30
CONST_BLOCKED_CONNECTION_TIMEOUT = 20


class MilleGrillesPikaBusConnection(StopListener):

    def __init__(self, context: MilleGrillesBusContext):
        super().__init__()
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__context = context

        self._connection: Optional[AsyncioConnection] = None
        self._channel: Optional[Channel] = None
        self._closing = False

        self.__event_connection_stopping = asyncio.Event()
        self.__loop: Optional[asyncio.EventLoop] = None

        context.register_stop_listener(self)

    async def stop(self):
        self.__event_connection_stopping.set()

    async def run(self):
        self.__loop = asyncio.get_event_loop()
        await asyncio.gather(
            self.run_ioloop(),
            self.maintenance_thread(),
        )

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

        loop = asyncio.get_event_loop()
        self._connection = AsyncioConnection(
            parameters,
            custom_ioloop=loop,
            on_open_callback=self.on_connection_open,
            on_open_error_callback=self.on_connection_open_error,
            on_close_callback=self.on_connection_closed)

        self.__logger.debug("Connection adapter : %s", self._connection)

    def close_connection(self):
        if self._connection.is_closing or self._connection.is_closed:
            self.__logger.info('Connection is closing or already closed')
        else:
            self.__logger.info('Closing connection')
            self._connection.close()

    def on_connection_open(self, _unused_connection: AsyncioConnection):
        """This method is called by pika once the connection to RabbitMQ has
        been established. It passes the handle to the connection object in
        case we need it, but in this case, we'll just mark it unused.

        :param pika.adapters.asyncio_connection.AsyncioConnection _unused_connection:
           The connection

        """
        self.__logger.info('Connection opened')
        self.open_channel()

    def on_connection_open_error(self, _unused_connection: AsyncioConnection, err: BaseException):
        """This method is called by pika if the connection to RabbitMQ
        can't be established.

        :param pika.adapters.asyncio_connection.AsyncioConnection _unused_connection:
           The connection
        :param Exception err: The error

        """
        self.__logger.error('Connection open failed: %s', err)
        self.reconnect()

    def on_connection_closed(self, _unused_connection: AsyncioConnection, reason: BaseException):
        """This method is invoked by pika when the connection to RabbitMQ is
        closed unexpectedly. Since it is unexpected, we will reconnect to
        RabbitMQ if it disconnects.

        :param pika.adapters.asyncio_connection.AsyncioConnection _unused_connection: The closed connection obj
        :param Exception reason: exception representing reason for loss of
            connection.

        """
        self._channel = None
        if self._closing:
            self._connection.ioloop.stop()
        else:
            self.__logger.warning('Connection closed, reconnect necessary: %s', reason)
            self.reconnect()

    def reconnect(self):
        """Will be invoked if the connection can't be opened or is
        closed. Indicates that a reconnect is necessary then stops the
        ioloop.

        """
        self.__loop.call_soon(self.__event_connection_stopping.set())

    def open_channel(self):
        """Open a new channel with RabbitMQ by issuing the Channel.Open RPC
        command. When RabbitMQ responds that the channel is open, the
        on_channel_open callback will be invoked by pika.

        """
        self.__logger.info('Creating a new channel')
        self._connection.channel(on_open_callback=self.on_channel_open)

    def on_channel_open(self, channel: Channel):
        """This method is invoked by pika when the channel has been opened.
        The channel object is passed in so we can make use of it.

        Since the channel is now open, we'll declare the exchange to use.

        :param pika.channel.Channel channel: The channel object

        """
        self.__logger.info('Channel opened')
        self._channel = channel
        self.add_on_channel_close_callback()

    def add_on_channel_close_callback(self):
        """This method tells pika to call the on_channel_closed method if
        RabbitMQ unexpectedly closes the channel.

        """
        self.__logger.info('Adding channel close callback')
        self._channel.add_on_close_callback(self.on_channel_closed)

    def on_channel_closed(self, channel: Channel, reason: str):
        """Invoked by pika when RabbitMQ unexpectedly closes the channel.
        :param pika.channel.Channel channel: The closed channel
        :param Exception reason: why the channel was closed
        """
        self.__logger.warning('Channel %i was closed: %s', channel, reason)
        self.close_connection()

    def close_channel(self):
        """Call to close the channel with RabbitMQ cleanly by issuing the
        Channel.Close RPC command.

        """
        self.__logger.info('Closing the channel')
        self._channel.close()

    async def run_ioloop(self):
        """Run the example consumer by connecting to RabbitMQ and then
        starting the IOLoop to block and allow the AsyncioConnection to operate.

        """
        while self.__context.stopping is False:
            self.__logger.info("run_ioloop Connecting to MQ bus")
            await self.connect()
            await self.__event_connection_stopping.wait()
            self.__event_connection_stopping.clear()  # Reset flag for reconnect if applicable
            self.__logger.debug("run_ioloop Disconnecting from MQ bus")

            # Close control channel
            if self._channel and self._channel.is_open:
                self._channel.close()

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
            self._channel.close()
            self.__logger.debug('__stop_connection Stopped')
