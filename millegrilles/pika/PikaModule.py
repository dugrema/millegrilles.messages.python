# Plug-in module pour pika 1.2 dans millegrilles messages
import logging
import pika
import ssl

from typing import Optional, Union

from pika.adapters.asyncio_connection import AsyncioConnection
from pika.adapters.utils.connection_workflow import AMQPConnectionWorkflowFailed

from millegrilles.messages.MessagesModule import MessagesModule


class PikaModule(MessagesModule):

    def __init__(self):
        super(MessagesModule, self).__init__()
        super(PikaModule, self).__init__()
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self.__connexion: Optional[AsyncioConnection] = None

    def est_connecte(self) -> bool:
        return self.__connexion is not None

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
                                      connection_attempts=5, retry_delay=5,
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

    def on_close(self, _unused_connection, reason):
        self.__logger.info("on_close: Connexion fermee, raison : %s", reason)
        self.__connexion = None
        self._consuming = False
