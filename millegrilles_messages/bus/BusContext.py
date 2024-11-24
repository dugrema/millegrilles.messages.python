import asyncio
import logging
import ssl
import signal
import threading
from asyncio import TaskGroup

from ssl import SSLContext, VerifyMode

from typing import Optional, Union, Callable, Awaitable

from millegrilles_messages.bus.BusConfiguration import MilleGrillesBusConfiguration
from millegrilles_messages.bus.BusExceptions import ConfigurationFileError
from millegrilles_messages.messages.CleCertificat import CleCertificat
from millegrilles_messages.messages.Constantes import ENV_REDIS_HOSTNAME, ENV_REDIS_PORT, ENV_REDIS_PASSWORD_PATH, \
    ENV_CA_PEM, ENV_CERT_PEM, ENV_KEY_PEM
from millegrilles_messages.messages.EnveloppeCertificat import EnveloppeCertificat, CertificatExpire
from millegrilles_messages.messages.FormatteurMessages import SignateurTransactionSimple, FormatteurMessageMilleGrilles
from millegrilles_messages.messages.ValidateurCertificats import ValidateurCertificatCache, ValidateurCertificatRedis
from millegrilles_messages.messages.ValidateurMessage import ValidateurMessage

LOGGER = logging.getLogger(__name__)

class ForceTerminateExecution(Exception):
    pass


class StopListener:
    """
    Extend this class to receive a stop callback when the application is stopping
    """

    def __init__(self, callback: Optional[Callable[[], Awaitable[None]]] = None):
        self.__callback = callback

    async def stop(self):
        # Hook
        if self.__callback:
            await self.__callback()


class MilleGrillesBusContext:

    def __init__(self, configuration: MilleGrillesBusConfiguration, load=True):
        self.__logger = logging.getLogger(__name__+'.'+self.__class__.__name__)
        self.__configuration = configuration
        self.__stop_event = asyncio.Event()
        self.__stop_listeners: list[StopListener] = list()

        self.__loop = asyncio.get_event_loop()
        self.__sync_event = threading.Event()

        # Signals
        signal.signal(signal.SIGINT, self.__exit_gracefully)
        signal.signal(signal.SIGTERM, self.__exit_gracefully)
        signal.signal(signal.SIGHUP, self.__reload_hup)

        # ###
        # Configuration loaded from disk - can be reloaded
        # ###
        self.__ssl_context: Optional[ssl.SSLContext] = None
        self.__clecert: Optional[CleCertificat] = None
        self.__ca: Optional[EnveloppeCertificat] = None
        self.__instance_id: Optional[str] = None
        self.__signateur: Optional[SignateurTransactionSimple] = None
        self.__formatteur: Optional[FormatteurMessageMilleGrilles] = None
        self.__verificateur_certificats: Optional[Union[ValidateurCertificatRedis, ValidateurCertificatCache]] = None
        self.__validateur_messages: Optional[ValidateurMessage] = None

        if load:
            # Initial load of the configuration
            self.reload()

    def __reload_hup(self, signum=None, frame=None):
        self.__logger.info("HUP received, reloading configuration from disk")
        self.reload()

    def reload(self):
        configuration = self.__configuration

        # Read all configuration from disk
        clecert, ca = load_certificates(configuration.key_path, configuration.cert_path, configuration.ca_path)
        signateur, formatteur = load_message_formatter(clecert, ca)

        if clecert.enveloppe.date_valide() is False:
            raise CertificatExpire()

        # Keep values in memory
        self.__ssl_context = _load_ssl_context(configuration)
        self.__clecert: CleCertificat = clecert
        self.__ca: EnveloppeCertificat = ca
        self.__instance_id: str = clecert.enveloppe.subject_common_name
        self.__signateur: SignateurTransactionSimple = signateur
        self.__formatteur: FormatteurMessageMilleGrilles = formatteur
        self.__verificateur_certificats: Union[ValidateurCertificatRedis, ValidateurCertificatCache] = self.load_validateur_certificats()
        self.__validateur_messages = ValidateurMessage(self.__verificateur_certificats)

    def __exit_gracefully(self, signum=None, frame=None):
        self.__logger.debug("Signal received: %d, closing" % signum)
        self.stop()

    def stop(self):
        self.__sync_event.set()

    async def run(self):
        async with TaskGroup() as group:
            group.create_task(self.__stop_thread())
            group.create_task(self.__sync_stop_thread())

    async def __sync_stop_thread(self):
        """
        Thread that listens to a non async process/callback toggling the sync_event flag.
        :return:
        """
        await asyncio.to_thread(self.__sync_event.wait)
        self.__stop_event.set()  # Toggle async stop thread

    async def __stop_thread(self):
        await self.__stop_event.wait()
        self.__sync_event.set()  # Ensure sync thread terminates
        for listener in self.__stop_listeners:
            try:
                await listener.stop()
            except Exception:
                self.__logger.exception("Error stopping listener %s" % listener)

    def load_validateur_certificats(self) -> Union[ValidateurCertificatRedis, ValidateurCertificatCache]:
        if self.configuration.redis_password_path:
            redis_configuration = {
                ENV_REDIS_HOSTNAME: self.configuration.redis_hostname,
                ENV_REDIS_PORT: str(self.configuration.redis_port),
                ENV_REDIS_PASSWORD_PATH: self.configuration.redis_password_path,
                ENV_CA_PEM: self.configuration.ca_path,
                ENV_CERT_PEM: self.configuration.cert_path,
                ENV_KEY_PEM: self.configuration.key_path,
            }
            return ValidateurCertificatRedis(self.ca, configuration=redis_configuration)
        else:
            return ValidateurCertificatCache(self.ca)

    async def wait(self, duration: Optional[Union[int,float]] = None):
        """
        Utility for waiting on the stop event.
        :param duration:
        :return:
        """
        if duration:
            try:
                await asyncio.wait_for(self.__stop_event.wait(), duration)
            except asyncio.TimeoutError:
                pass
        else:
            await self.__stop_event.wait()

    @property
    def stopping(self):
        return self.__stop_event.is_set() or self.__sync_event.is_set()

    def register_stop_listener(self, listener: StopListener):
        """
        Register to get a notification when stopping the application.
        :param listener:
        :return:
        """
        self.__stop_listeners.append(listener)

    @property
    def configuration(self):
        return self.__configuration

    @property
    def ssl_context(self):
        return self.__ssl_context

    @property
    def signing_key(self) -> CleCertificat:
        return self.__clecert

    @property
    def ca(self) -> EnveloppeCertificat:
        return self.__ca

    @property
    def signateur(self):
        return self.__signateur

    @property
    def formatteur(self):
        return self.__formatteur

    @property
    def verificateur_certificats(self):
        return self.__verificateur_certificats

    @property
    def validateur_message(self):
        return self.__validateur_messages

    @property
    def instance_id(self):
        return self.__instance_id


def _load_ssl_context(configuration: MilleGrillesBusConfiguration) -> ssl.SSLContext:
    ssl_context = SSLContext()

    LOGGER.debug("Load web certificate %s" % configuration.cert_path)
    try:
        ssl_context.load_cert_chain(configuration.cert_path, configuration.key_path)
    except FileNotFoundError:
        files = "%s or %s" % (configuration.cert_path, configuration.key_path)
        raise ConfigurationFileError(files)

    try:
        ssl_context.load_verify_locations(cafile=configuration.ca_path)
    except FileNotFoundError:
        raise ConfigurationFileError(configuration.ca_path)

    ssl_context.verify_mode = VerifyMode.CERT_REQUIRED

    return ssl_context

def load_certificates(key_path: str, cert_path: str, ca_path: str) -> (CleCertificat, EnveloppeCertificat):
    clecert = CleCertificat.from_files(key_path, cert_path)
    clecert.cle_correspondent()  # Ensures the cert/key match
    ca = EnveloppeCertificat.from_file(ca_path)
    idmg = ca.idmg
    if clecert.enveloppe.idmg != idmg:
        raise ValueError("CA and Cert mismatch on IDMG")

    return clecert, ca


def load_message_formatter(clecert: CleCertificat, ca: EnveloppeCertificat) -> (SignateurTransactionSimple, FormatteurMessageMilleGrilles):
    enveloppe = clecert.enveloppe
    idmg = enveloppe.idmg

    signateur = SignateurTransactionSimple(clecert)
    formatteur = FormatteurMessageMilleGrilles(idmg, signateur, ca)

    return signateur, formatteur
