# Parsing de la configuration d'un service/container
from typing import Optional

from docker.types import SecretReference, NetworkAttachmentConfig, Resources, RestartPolicy, ServiceMode, \
    ConfigReference, EndpointSpec, Mount


class ConfigurationService:
    """
    Converti format config MilleGrilles en format du module docker
    """

    def __init__(self, configuration: dict):
        self.__configuration = configuration
        self.__parsed: Optional[dict] = None

        self.__name: Optional[str] = None
        self.__hostname: Optional[str] = None
        self.__args: Optional[list] = None
        self.__image: Optional[str] = None
        self.__environment: Optional[list] = None
        self.__mounts: Optional[list] = None
        self.__constraints: Optional[list] = None
        self.__config: Optional[list] = None
        self.__secrets: Optional[list] = None
        self.__endpoint_spec: Optional[dict] = None
        self.__networks: Optional[list] = None
        self.__labels: Optional[list] = None
        self.__resources: Optional[Resources] = None
        self.__mode: Optional[ServiceMode] = None
        self.__restart_policy: Optional[RestartPolicy] = None

    def parse(self):
        self.__name = self.__configuration['name']
        self.__image = self.__configuration['image']

        try:
            self.__hostname = self.__configuration['hostname']
        except KeyError:
            pass

        try:
            self.__args = self.__configuration['args']
        except KeyError:
            pass

        try:
            self.__constraints = self.__configuration['constraints']
        except KeyError:
            pass

        try:
            self.__networks = self.__configuration['networks']
        except KeyError:
            pass

        self.parse_resources()
        self.parse_restart_policy()
        self.parse_service_mode()
        self.parse_mounts()
        self.parse_env()
        self.parse_configs()
        self.parse_secrets()
        self.parse_networks()

    def parse_resources(self):
        try:
            resources = self.__configuration['resources']
            self.__resources = Resources(**resources)
        except KeyError:
            pass

    def parse_restart_policy(self):
        try:
            policy = self.__configuration['restart_policy']
            self.__restart_policy = RestartPolicy(**policy)
        except KeyError:
            pass

    def parse_service_mode(self):
        try:
            config = self.__configuration['mode']
            self.__restart_policy = ServiceMode(**config)
        except KeyError:
            pass

    def parse_mounts(self):
        # # Mounts
        # config_mounts = config_service.get('mounts')
        # if config_mounts:
        #     if not mode_container:
        #         dict_config_docker['mounts'] = [self.__mapping(mount) for mount in config_mounts]
        #     else:
        #         self.__logger.warning("Mounts : Format des containers, ignorer pour l'instant")
        #         mounts = list()
        #         for mount in config_mounts:
        #             mount_obj = Mount(mount['target'], mount['source'], mount['type'])
        #             mounts.append(mount_obj)
        #         dict_config_docker['mounts'] = mounts
        pass

    def parse_env(self):
        try:
            env_config = self.__configuration['env'].copy()
        except KeyError:
            env_config = dict()

        #env_config["INSTANCE_ID"] = self.__service_monitor.noeud_id
        #env_config["MG_IDMG"] = self.__service_monitor.idmg

        # connexion_mq = self.__service_monitor.get_info_connexion_mq(nowait=True)
        # for key, value in connexion_mq.items():
        #     # config_env.append(key + "=" + str(value))
        #     config_env_dict[key] = str(value)
        #
        # # Toujours ajouter l'id du noeud, le IDMG, MQ connexion params
        # # config_env.append("MG_NOEUD_ID=" + self.__service_monitor.noeud_id)
        # # config_env.append("MG_IDMG=" + self.__service_monitor.idmg)
        # config_env_dict["MG_NOEUD_ID"] = self.__service_monitor.noeud_id
        # config_env_dict["MG_IDMG"] = self.__service_monitor.idmg

        config_env_list = ['='.join(i) for i in env_config.items()]
        self.__configuration = config_env_list

    def parse_configs(self):
        # # Configs
        # config_configs = config_service.get('configs')
        # dates_configs = dict()
        # if config_configs:
        #     liste_configs = list()
        #     for config in config_configs:
        #         self.__logger.debug("Mapping configs %s" % config)
        #         config_name = config['name']
        #         try:
        #             config_dict = self.__trouver_config(config_name)
        #
        #             config_reference = config_dict['config_reference']
        #             config_reference['filename'] = config['filename']
        #             config_reference['uid'] = config.get('uid') or 0
        #             config_reference['gid'] = config.get('gid') or 0
        #             config_reference['mode'] = config.get('mode') or 0o444
        #             liste_configs.append(ConfigReference(**config_reference))
        #
        #             date_config = config_dict.get('date')
        #             if date_config:
        #                 dates_configs[config_name] = date_config
        #         except AttributeError as ae:
        #             self.__logger.error("Parametres de configuration manquants pour service %s : %s" % (config_name, str(ae)))
        #
        #     dict_config_docker['configs'] = liste_configs
        pass

    def parse_secrets(self):
        # # Secrets
        # config_secrets = config_service.get('secrets')
        # if config_secrets:
        #     liste_secrets = list()
        #     for secret in config_secrets:
        #         self.__logger.debug("Mapping secret %s" % secret)
        #         secret_name = secret['name']
        #         if secret.get('regex'):
        #             references = self.__trouver_secret_regex(secret)
        #             for secret_reference in references:
        #                 # secret_reference['filename'] = secret['filename']
        #                 secret_reference['uid'] = secret.get('uid') or 0
        #                 secret_reference['gid'] = secret.get('gid') or 0
        #                 secret_reference['mode'] = secret.get('mode') or 0o444
        #                 liste_secrets.append(SecretReference(**secret_reference))
        #         else:
        #             if secret.get('match_config'):
        #                 secret_reference = self.__trouver_secret_matchdate(secret_name, dates_configs)
        #             else:
        #                 secret_reference = self.trouver_secret(secret_name)
        #
        #             secret_reference['filename'] = secret['filename']
        #             secret_reference['uid'] = secret.get('uid') or 0
        #             secret_reference['gid'] = secret.get('gid') or 0
        #             secret_reference['mode'] = secret.get('mode') or 0o444
        #
        #             del secret_reference['date']  # Cause probleme lors du chargement du secret
        #             liste_secrets.append(SecretReference(**secret_reference))
        #
        #     dict_config_docker['secrets'] = liste_secrets
        pass

    def parse_labels(self):
        # # Service labels
        # config_labels = config_service.get('labels')
        # updated_labels = dict()
        # dict_config_docker['labels'] = updated_labels
        #
        # if config_labels:
        #     for key, value in config_labels.items():
        #         value = self.__mapping(value)
        #         updated_labels[key] = value
        #
        # if kwargs.get('application'):
        #     updated_labels['application'] = kwargs.get('application')
        #     if config_service.get('certificat_compte'):
        #         updated_labels['certificat'] = 'true'
        #         updated_labels['certificat_nom'] = config_service['certificat_compte']
        #     dict_config_docker['labels'] = updated_labels
        #
        # # Container labels
        # config_container_labels = config_service.get('container_labels')
        # if config_container_labels:
        #     updated_labels = dict()
        #     for key, value in config_container_labels.items():
        #         value = self.__mapping(value)
        #         updated_labels[key] = value
        #     dict_config_docker['container_labels'] = updated_labels
        pass

    def parse_networks(self):
        # # Networks
        # config_networks = config_service.get('networks')
        # if config_networks:
        #     networks = list()
        #     for network in config_networks:
        #         network['target'] = self.__mapping(network['target'])
        #         networks.append(NetworkAttachmentConfig(**network))
        #
        #     dict_config_docker['networks'] = networks
        pass

    def parse_endpoint_specs(self):
        # # Ports
        # config_endpoint_spec = config_service.get('endpoint_spec')
        # if config_endpoint_spec:
        #     ports = dict()
        #     mode = config_endpoint_spec.get('mode') or 'vip'
        #     for port in config_endpoint_spec.get('ports'):
        #         published_port = port['published_port']
        #         target_port = port['target_port']
        #         protocol = port.get('protocol') or 'tcp'
        #         publish_mode = port.get('publish_mode')
        #
        #         if protocol or publish_mode:
        #             ports[published_port] = (target_port, protocol, publish_mode)
        #         else:
        #             ports[published_port] = target_port
        #
        #     dict_config_docker['endpoint_spec'] = EndpointSpec(mode=mode, ports=ports)
        pass

    def generer_docker_config(self) -> dict:
        config = {
            'name': self.__name,
            'image': self.__image,
        }

        if self.__hostname is not None:
            config['hostname'] = self.__hostname

        if self.__args is not None:
            config['args'] = self.__args

        if self.__environment is not None:
            config['env'] = self.__environment

        if self.__restart_policy is not None:
            config['restart_policy'] = self.__restart_policy

        if self.__mode is not None:
            config['mode'] = self.__mode

        if self.__labels is not None:
            config['labels'] = self.__labels

        if self.__networks is not None:
            config['networks'] = self.__networks

        if self.__mounts is not None:
            config['mounts'] = self.__mounts

        if self.__constraints is not None:
            config['constraints'] = self.__constraints

        if self.__config is not None:
            config['config'] = self.__config

        if self.__secrets is not None:
            config['secrets'] = self.__secrets

        if self.__endpoint_spec is not None:
            config['endpoint_spec'] = self.__endpoint_spec

        if self.__resources is not None:
            config['resources'] = self.__resources

        return config


class ConfigurationContainer:

    def __init__(self):
        pass