import os

from millegrilles_messages.messages.Constantes import ENV_REDIS_HOSTNAME, ENV_REDIS_PASSWORD_PATH, ENV_REDIS_PORT

ENV_CERT_PATH = 'CERT_PATH'
ENV_KEY_PATH = 'KEY_PATH'
ENV_CA_PATH = 'CA_PATH'
ENV_MQ_HOSTNAME = 'MQ_HOSTNAME'
ENV_MQ_PORT = 'MQ_PORT'
# ENV_REDIS_HOSTNAME = 'REDIS_HOSTNAME'
# ENV_REDIS_PORT = 'REDIS_PORT'
# ENV_REDIS_PASSWORD_PATH = 'REDIS_PASSWORD_PATH'

DEFAULT_CERT="/run/secrets/cert.pem"
DEFAULT_KEY="/run/secrets/key.pem"
DEFAULT_CA="/run/secrets/ca.pem"
DEFAULT_MQ_HOSTNAME="mq"
DEFAULT_MQ_PORT=5673
DEFAULT_REDIS_HOSTNAME="redis"
DEFAULT_REDIS_PORT=6379
DEFAULT_REDIS_PASSWORD_PATH='/run/secrets/redis.txt'


class MilleGrillesBusConfiguration:

    def __init__(self):
        self.cert_path = DEFAULT_CERT
        self.key_path = DEFAULT_KEY
        self.ca_path = DEFAULT_CA
        self.mq_hostname = DEFAULT_MQ_HOSTNAME
        self.mq_port = DEFAULT_MQ_PORT
        self.redis_hostname = DEFAULT_REDIS_HOSTNAME
        self.redis_port = DEFAULT_REDIS_PORT
        self.redis_password_path = DEFAULT_REDIS_PASSWORD_PATH

    def parse_config(self):
        self.cert_path = os.environ.get(ENV_CERT_PATH) or self.cert_path
        self.key_path = os.environ.get(ENV_KEY_PATH) or self.key_path
        self.ca_path = os.environ.get(ENV_CA_PATH) or self.ca_path
        self.mq_hostname = os.environ.get(ENV_MQ_HOSTNAME) or self.mq_hostname
        self.redis_hostname = os.environ.get(ENV_REDIS_HOSTNAME) or self.redis_hostname
        self.redis_password_path = os.environ.get(ENV_REDIS_PASSWORD_PATH) or self.redis_password_path

        mq_port = os.environ.get(ENV_MQ_PORT)
        if mq_port:
            self.mq_port = int(mq_port)

        redis_port = os.environ.get(ENV_REDIS_PORT)
        if redis_port:
            self.redis_port = int(redis_port)

    @staticmethod
    def load():
        config = MilleGrillesBusConfiguration()
        config.parse_config()
        config.reload()
        return config

    def reload(self):
        pass  # Hook for sub-classes
