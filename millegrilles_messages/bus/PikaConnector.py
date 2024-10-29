import logging
import pika
import ssl

from pika.adapters.asyncio_connection import AsyncioConnection

from millegrilles_messages.messages.EnveloppeCertificat import EnveloppeCertificat
from millegrilles_messages.bus.BusContext import MilleGrillesBusContext


class MilleGrillesPikaConnector:

    def __init__(self, context: MilleGrillesBusContext):
        self.__logger = logging.getLogger(__name__+'.'+self.__class__.__name__)
        self.__context = context

    async def run(self):
        pass

    async def connect(self):
        hostname = self.__context.configuration.mq_hostname
        port = self.__context.configuration.mq_port

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
                                      port=port,
                                      virtual_host=idmg,
                                      credentials=pika.credentials.ExternalCredentials(),
                                      ssl_options=ssl_options,
                                      connection_attempts=self.__pika_configuration.connection_attempts,
                                      retry_delay=self.__pika_configuration.retry_delay,
                                      heartbeat=self.__pika_configuration.heartbeat,
                                      blocked_connection_timeout=self.__pika_configuration.blocked_connection_timeout)]

        connection_adapter = AsyncioConnection.create_connection(parameters, on_done=self.on_connect_done)

        self.__logger.debug("Connection adapter : %s", connection_adapter)
