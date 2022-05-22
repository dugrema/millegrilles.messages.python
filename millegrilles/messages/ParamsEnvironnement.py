import os

from millegrilles.messages import Constantes

from typing import Optional


CONST_MQ_PARAMS = [
    Constantes.ENV_MQ_HOSTNAME,
    Constantes.ENV_MQ_PORT,
    Constantes.ENV_CA_PEM,
    Constantes.ENV_CERT_PEM,
    Constantes.ENV_KEY_PEM,
    Constantes.ENV_MQ_CONNECTION_ATTEMPTS,
    Constantes.ENV_MQ_RETRY_DELAY,
    Constantes.ENV_MQ_HEARTBEAT,
    Constantes.ENV_MQ_BLOCKED_CONNECTION_TIMEOUT,
]

CONST_REDIS_PARAMS = [
    Constantes.ENV_REDIS_HOSTNAME,
    Constantes.ENV_REDIS_PORT,
    Constantes.ENV_REDIS_USERNAME,
    Constantes.ENV_REDIS_PASSWORD,
    Constantes.ENV_REDIS_PASSWORD_PATH,

    # Env certs, meme params que MQ
    Constantes.ENV_CA_PEM,
    Constantes.ENV_CERT_PEM,
    Constantes.ENV_KEY_PEM,
]


class ConfigurationPika:
    """
    Configuration de connexion avec Pika (pour RabbitMQ)
    """

    def __init__(self):
        self.hostname: Optional[str] = None
        self.port: Optional[int] = None
        self.ca_pem_path: Optional[str] = None
        self.cert_pem_path: Optional[str] = None
        self.key_pem_path: Optional[str] = None

        # Valeurs avec defaults
        self.connection_attempts = 2
        self.retry_delay = 10
        self.heartbeat = 30
        self.blocked_connection_timeout = 10

    def get_env(self) -> dict:
        """
        Extrait l'information pertinente pour pika de os.environ
        :return: Configuration dict
        """
        config = dict()
        for opt_param in CONST_MQ_PARAMS:
            value = os.environ.get(opt_param)
            if value is not None:
                config[opt_param] = value

        return config

    def parse_config(self, configuration: dict):
        """
        Conserver l'information de configuration
        :param configuration:
        :return:
        """
        dict_params = self.get_env()
        if configuration is not None:
            dict_params.update(configuration)

        self.hostname = dict_params.get(Constantes.ENV_MQ_HOSTNAME) or 'mq'
        self.port = int(dict_params.get(Constantes.ENV_MQ_PORT) or '5673')
        self.ca_pem_path = dict_params[Constantes.ENV_CA_PEM]
        self.cert_pem_path = dict_params[Constantes.ENV_CERT_PEM]
        self.key_pem_path = dict_params[Constantes.ENV_KEY_PEM]

        # Valeurs avec defaults
        self.connection_attempts = dict_params.get(
            Constantes.ENV_MQ_CONNECTION_ATTEMPTS) or self.connection_attempts
        self.retry_delay = dict_params.get(
            Constantes.ENV_MQ_RETRY_DELAY) or self.retry_delay
        self.heartbeat = dict_params.get(
            Constantes.ENV_MQ_HEARTBEAT) or self.heartbeat
        self.blocked_connection_timeout = dict_params.get(
            Constantes.ENV_MQ_BLOCKED_CONNECTION_TIMEOUT) or self.blocked_connection_timeout

    def __str__(self):
        return 'ConfigurationPika %s:%s' % (self.hostname, self.port)


class ConfigurationRedis:
    """
    Configuration de connexion avec Pika (pour RabbitMQ)
    """

    def __init__(self):
        self.hostname: Optional[str] = None
        self.port: Optional[int] = None
        self.username: Optional[str] = None
        self.password: Optional[str] = None

        self.ca_pem_path: Optional[str] = None
        self.cert_pem_path: Optional[str] = None
        self.key_pem_path: Optional[str] = None

    def get_env(self) -> dict:
        """
        Extrait l'information pertinente pour pika de os.environ
        :return: Configuration dict
        """
        config = dict()
        for opt_param in CONST_REDIS_PARAMS:
            value = os.environ.get(opt_param)
            if value is not None:
                config[opt_param] = value

        return config

    def parse_config(self, configuration: Optional[dict] = None):
        """
        Conserver l'information de configuration
        :param configuration:
        :return:
        """
        dict_params = self.get_env()
        if configuration is not None:
            dict_params.update(configuration)

        self.hostname = dict_params.get(Constantes.ENV_REDIS_HOSTNAME) or 'redis'
        self.port = int(dict_params.get(Constantes.ENV_REDIS_PORT) or '6379')
        self.username = dict_params.get(Constantes.ENV_REDIS_USERNAME) or 'client_nodejs'

        # Charger le mot de pass (mandatory)
        try:
            self.password = dict_params[Constantes.ENV_REDIS_PASSWORD]
        except KeyError:
            # Fallback sur password path, on charge immediatement
            path_password = dict_params[Constantes.ENV_REDIS_PASSWORD_PATH]
            with open(path_password, 'r') as fichier:
                password = fichier.read()
                self.password = password.splitlines()[0].strip()

        try:
            self.ca_pem_path = dict_params[Constantes.ENV_CA_PEM]
        except KeyError:
            pass  # CA optionnel. Pour validateur certs, on a deja le CA en parametres

        self.cert_pem_path = dict_params[Constantes.ENV_CERT_PEM]
        self.key_pem_path = dict_params[Constantes.ENV_KEY_PEM]

    def __str__(self):
        return 'ConfigurationRedis %s:%s' % (self.hostname, self.port)


class ConfigurationWebServer:

    def __init__(self):
        self.__port: Optional[int] = None

    def charger_env(self):
        self.__port = int(os.environ.get(Constantes.ENV_WEB_PORT) or '8080')
