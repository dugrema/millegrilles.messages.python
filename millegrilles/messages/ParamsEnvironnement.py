import os

import Constantes

from typing import Optional


class ConfigurationPika:
    """
    Configuration de connexion avec Pika (pour RabbitMQ)
    """

    def __init__(self):
        self.__hostname: Optional[str] = None
        self.__port: Optional[int] = None
        self.__ca_pem_path: Optional[str] = None
        self.__cert_pem_path: Optional[str] = None
        self.__key_pem_path: Optional[str] = None

    def get_env(self) -> dict:
        """
        Extrait l'information pertinente pour pika de os.environ
        :return: Configuration dict
        """
        config = dict()
        config[Constantes.ENV_MQ_HOSTNAME] = os.environ.get(Constantes.ENV_MQ_HOSTNAME) or 'mq'
        config[Constantes.ENV_MQ_PORT] = os.environ.get(Constantes.ENV_MQ_PORT) or '5673'
        config[Constantes.ENV_CA_PEM] = os.environ.get(Constantes.ENV_CA_PEM)
        config[Constantes.ENV_CERT_PEM] = os.environ.get(Constantes.ENV_CERT_PEM)
        config[Constantes.ENV_KEY_PEM] = os.environ.get(Constantes.ENV_KEY_PEM)
        return config

    def parse_config(self, configuration: dict):
        """
        Conserver l'information de configuration
        :param configuration:
        :return:
        """
        self.__hostname = configuration.get(Constantes.ENV_MQ_HOSTNAME) or 'mq'
        self.__port = int(configuration.get(Constantes.ENV_MQ_PORT) or '5673')
        self.__ca_pem_path = configuration[Constantes.ENV_CA_PEM]
        self.__cert_pem_path = configuration[Constantes.ENV_CERT_PEM]
        self.__key_pem_path = configuration[Constantes.ENV_KEY_PEM]


class ConfigurationWebServer:

    def __init__(self):
        self.__port: Optional[int] = None

    def charger_env(self):
        self.__port = int(os.environ.get(Constantes.ENV_WEB_PORT) or '8080')

