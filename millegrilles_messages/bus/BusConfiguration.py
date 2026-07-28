import os
import logging
from typing import Optional

from cryptography.x509 import ExtensionNotFound

from millegrilles_messages.messages.CleCertificat import CleCertificat
from millegrilles_messages.messages.Constantes import ENV_REDIS_HOSTNAME, ENV_REDIS_PASSWORD_PATH, ENV_REDIS_PORT, \
    ENV_REDIS_USERNAME, ENV_DEV
from millegrilles_messages.messages.EnveloppeCertificat import EnveloppeCertificat

ENV_CERT_PATH = 'CERT_PATH'
ENV_KEY_PATH = 'KEY_PATH'
ENV_CA_PATH = 'CA_PATH'
ENV_MQ_HOSTNAME = 'MQ_HOSTNAME'
ENV_MQ_PORT = 'MQ_PORT'
ENV_MTLS_PORT = 'MTLS_PORT'

DEFAULT_CERT="/run/secrets/cert.pem"
DEFAULT_KEY="/run/secrets/key.pem"
DEFAULT_CA="/run/secrets/ca.pem"
DEFAULT_MQ_HOSTNAME="mq"
DEFAULT_MQ_PORT=5673
DEFAULT_REDIS_HOSTNAME="redis"
DEFAULT_REDIS_USERNAME="client_nodejs"
DEFAULT_REDIS_PORT=6379
DEFAULT_REDIS_PASSWORD_PATH='/run/secrets/redis.txt'
DEFAULT_MTLS_PORT=444


LOGGER = logging.getLogger(__name__)

class MilleGrillesBusConfiguration:

    def __init__(self):
        self.cert_path = DEFAULT_CERT
        self.key_path = DEFAULT_KEY
        self.ca_path = DEFAULT_CA
        self.mq_hostname = DEFAULT_MQ_HOSTNAME
        self.mq_port = DEFAULT_MQ_PORT
        self.mtls_port = DEFAULT_MTLS_PORT
        self.redis_hostname = DEFAULT_REDIS_HOSTNAME
        self.redis_port = DEFAULT_REDIS_PORT
        self.redis_username = DEFAULT_REDIS_USERNAME
        self.redis_password_path = DEFAULT_REDIS_PASSWORD_PATH
        self.__signing_key: Optional[CleCertificat] = None
        self.__ca: Optional[EnveloppeCertificat] = None
        self.dev = False

    def parse_config(self):
        self.cert_path = os.environ.get(ENV_CERT_PATH) or self.cert_path
        self.key_path = os.environ.get(ENV_KEY_PATH) or self.key_path
        self.ca_path = os.environ.get(ENV_CA_PATH) or self.ca_path
        self.mq_hostname = os.environ.get(ENV_MQ_HOSTNAME) or self.mq_hostname
        self.redis_hostname = os.environ.get(ENV_REDIS_HOSTNAME) or self.redis_hostname
        self.redis_username = os.environ.get(ENV_REDIS_USERNAME) or self.redis_username
        self.redis_password_path = os.environ.get(ENV_REDIS_PASSWORD_PATH) or self.redis_password_path
        self.dev = True if os.environ.get(ENV_DEV) else False

        mq_port = os.environ.get(ENV_MQ_PORT)
        if mq_port:
            self.mq_port = int(mq_port)

        redis_port = os.environ.get(ENV_REDIS_PORT)
        if redis_port:
            self.redis_port = int(redis_port)

        mtls_port = os.environ.get(ENV_MTLS_PORT)
        if mtls_port:
            self.mtls_port = int(mtls_port)

    @staticmethod
    def load():
        config = MilleGrillesBusConfiguration()
        config.parse_config()
        config.reload()

        return config

    def reload(self):
        # Attempt to load certificates
        try:
            self.__load_certificates(self.key_path, self.cert_path, self.ca_path)
        except FileNotFoundError:
            LOGGER.warning("Error loading certificate files (signing key, CA)")

    def __load_certificates(self, key_path: str, cert_path: str, ca_path: str):
        clecert = CleCertificat.from_files(key_path, cert_path)
        clecert.cle_correspondent()  # Ensures the cert/key match
        ca = EnveloppeCertificat.from_file(ca_path)
        idmg = ca.idmg
        if clecert.enveloppe.idmg != idmg:
            raise ValueError("CA and Cert mismatch on IDMG")

        self.__signing_key = clecert
        self.__ca = ca

    @property
    def signing_key(self) -> Optional[CleCertificat]:
        return self.__signing_key

    @property
    def ca(self) -> Optional[EnveloppeCertificat]:
        return self.__ca

    @property
    def instance_id(self) -> Optional[str]:
        if self.__signing_key:
            return self.__signing_key.enveloppe.subject_common_name
        return None

    @property
    def securite(self) -> Optional[str]:
        if self.__signing_key:
            try:
                return self.__signing_key.enveloppe.get_exchanges[0]
            except (TypeError, ValueError, IndexError, ExtensionNotFound):
                pass
        return None

    @property
    def idmg(self) -> Optional[str]:
        if self.__signing_key:
            return self.__signing_key.enveloppe.idmg
        return None
