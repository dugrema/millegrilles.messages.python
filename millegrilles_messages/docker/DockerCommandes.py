import asyncio
import base64
import docker
import json
import logging
import math

from typing import Optional, Union

from docker import DockerClient
from docker.errors import APIError, NotFound
from docker.models.services import Service
from docker.types import ServiceMode


from millegrilles_messages.docker.DockerHandler import CommandeDocker


class CommandeListerContainers(CommandeDocker):

    def __init__(self, callback=None, aio=False, filters: dict = None):
        super().__init__(callback, aio)
        self.__filters = filters

    def executer(self, docker_client: DockerClient):
        liste = docker_client.containers.list(filters=self.__filters)
        self.callback(liste)

    async def get_liste(self) -> list:
        resultat = await self.attendre()
        liste = resultat['args'][0]
        return liste


class CommandeListerServices(CommandeDocker):

    def __init__(self, callback=None, aio=False, filters: dict = None):
        super().__init__(callback, aio)
        self.__filters = filters

    def executer(self, docker_client: DockerClient):
        liste = docker_client.services.list(filters=self.__filters)
        self.callback(liste)

    async def get_liste(self) -> list[Service]:
        resultat = await self.attendre()
        liste = resultat['args'][0]
        return liste


class CommandeRedemarrerService(CommandeDocker):

    def __init__(self, nom_service: str, callback=None, aio=False, id_only=True):
        super().__init__(callback, aio)
        self.__nom_service = nom_service

        self.facteur_throttle = 1.5

    def executer(self, docker_client: DockerClient):
        service = docker_client.services.get(self.__nom_service)
        attrs = service.attrs
        resultat = False
        try:
            spec = attrs['Spec']
            mode = spec['Mode']
            replicated = mode['Replicated']
            replicas = replicated['Replicas']
            if replicas > 0:
                resultat = service.force_update()
        except KeyError:
            pass

        self.callback(resultat)


class CommandeMajService(CommandeDocker):

    def __init__(self, nom_service: str, config: dict, callback=None, aio=True):
        super().__init__(callback, aio)
        self.__nom_service = nom_service
        self.__config = config

        self.facteur_throttle = 1.5

    def executer(self, docker_client: DockerClient):
        service = docker_client.services.get(self.__nom_service)
        service.update(**self.__config)
        self.callback(True)


class CommandeDemarrerService(CommandeDocker):

    def __init__(self, nom_service: str, replicas=1, callback=None, aio=True):
        super().__init__(callback, aio)
        self.__nom_service = nom_service
        self.__replicas = replicas

        self.facteur_throttle = 1.5

    def executer(self, docker_client: DockerClient):
        service = docker_client.services.get(self.__nom_service)
        resultat = service.scale(self.__replicas)
        self.callback(resultat)

    async def get_resultat(self) -> bool:
        resultats = await self.attendre()
        succes = resultats['args'][0]
        return succes


class CommandeArreterService(CommandeDocker):

    def __init__(self, nom_service: str, callback=None, aio=True):
        super().__init__(callback, aio)
        self.__nom_service = nom_service

        self.facteur_throttle = 0.5

    def executer(self, docker_client: DockerClient):
        service = docker_client.services.get(self.__nom_service)
        resultat = service.scale(0)
        self.callback(resultat)

    async def get_resultat(self) -> bool:
        resultats = await self.attendre()
        succes = resultats['args'][0]
        return succes


class CommandeSupprimerService(CommandeDocker):

    def __init__(self, nom_service: str, callback=None, aio=True):
        super().__init__(callback, aio)
        self.__nom_service = nom_service

        self.facteur_throttle = 0.5

    def executer(self, docker_client: DockerClient):
        service = docker_client.services.get(self.__nom_service)
        resultat = service.remove()
        self.callback(resultat)

    async def get_resultat(self) -> bool:
        resultats = await self.attendre()
        succes = resultats['args'][0]
        return succes


class CommandeListerConfigs(CommandeDocker):

    def __init__(self, callback=None, aio=False, filters: dict = None, id_only=True):
        super().__init__(callback, aio)
        self.__filters = filters
        self.__id_only = id_only

    def executer(self, docker_client: DockerClient):
        liste = docker_client.configs.list(filters=self.__filters)

        resultat = liste
        if self.__id_only:
            resultat = dict()
            for c in liste:
                id_c = c.id
                name = c.name
                resultat[name] = id_c

        self.callback(resultat)

    async def get_resultat(self) -> list:
        resultat = await self.attendre()
        liste = resultat['args'][0]
        return liste


class CommandeListerSecrets(CommandeDocker):

    def __init__(self, callback=None, aio=False, filters: dict = None, id_only=True):
        super().__init__(callback, aio)
        self.__filters = filters
        self.__id_only = id_only

    def executer(self, docker_client: DockerClient):
        liste = docker_client.secrets.list(filters=self.__filters)

        resultat = liste
        if self.__id_only:
            resultat = dict()
            for c in liste:
                id_c = c.id
                name = c.name
                resultat[name] = id_c

        self.callback(resultat)

    async def get_resultat(self) -> list:
        resultat = await self.attendre()
        liste = resultat['args'][0]
        return liste


class CommandeAjouterConfiguration(CommandeDocker):

    def __init__(self, nom: str, data: Union[dict, str, bytes], labels: dict = None, callback=None, aio=False):
        super().__init__(callback, aio)
        self.__nom = nom
        self.__labels = labels

        if isinstance(data, dict):
            data_string = json.dumps(data).encode('utf-8')
        elif isinstance(data, str):
            data_string = data.encode('utf-8')
        elif isinstance(data, bytes):
            data_string = data
        else:
            raise ValueError("Type data non supporte")

        self.__data = data_string

        self.facteur_throttle = 0.25

    def executer(self, docker_client: DockerClient):
        reponse = docker_client.configs.create(name=self.__nom, data=self.__data, labels=self.__labels)
        self.callback(reponse)

    async def get_resultat(self) -> list:
        resultat = await self.attendre()
        return resultat['args'][0]


class CommandeSupprimerConfiguration(CommandeDocker):

    def __init__(self, nom: str, callback=None, aio=False):
        super().__init__(callback, aio)
        self.__nom = nom
        self.facteur_throttle = 0.25

    def executer(self, docker_client: DockerClient):
        config = docker_client.configs.get(self.__nom)
        reponse = config.remove()
        self.callback(reponse)

    async def get_resultat(self) -> list:
        resultat = await self.attendre()
        return resultat['args'][0]


class CommandeGetConfiguration(CommandeDocker):

    def __init__(self, nom: str, callback=None, aio=False):
        super().__init__(callback, aio)
        self.__nom = nom
        self.facteur_throttle = 0.25

    def executer(self, docker_client: DockerClient):
        config = docker_client.configs.get(self.__nom)
        self.callback(config)

    async def get_config(self) -> list:
        resultat = await self.attendre()
        return resultat['args'][0]

    async def get_data(self) -> str:
        resultat = await self.attendre()
        config = resultat['args'][0]
        data = config.attrs['Spec']['Data']
        data_str = base64.b64decode(data)
        if isinstance(data_str, bytes):
            data_str = data_str.decode('utf-8')

        return data_str


class CommandeAjouterSecret(CommandeDocker):

    def __init__(self, nom: str, data: Union[dict, str, bytes], labels: dict = None, callback=None, aio=False):
        super().__init__(callback, aio)
        self.__nom = nom
        self.__labels = labels

        if isinstance(data, dict):
            data_string = json.dumps(data).encode('utf-8')
        elif isinstance(data, str):
            data_string = data.encode('utf-8')
        elif isinstance(data, bytes):
            data_string = data
        else:
            raise ValueError("Type data non supporte")

        self.__data = data_string

        self.facteur_throttle = 0.25

    def executer(self, docker_client: DockerClient):
        reponse = docker_client.secrets.create(name=self.__nom, data=self.__data, labels=self.__labels)
        self.callback(reponse)

    async def get_resultat(self) -> list:
        resultat = await self.attendre()
        return resultat['args'][0]


class CommandeSupprimerSecret(CommandeDocker):

    def __init__(self, nom: str, callback=None, aio=False):
        super().__init__(callback, aio)
        self.__nom = nom
        self.facteur_throttle = 0.25

    def executer(self, docker_client: DockerClient):
        config = docker_client.secrets.get(self.__nom)
        reponse = config.remove()
        self.callback(reponse)

    async def get_resultat(self) -> list:
        resultat = await self.attendre()
        return resultat['args'][0]


class CommandeCreerService(CommandeDocker):

    def __init__(self, image: str, configuration: dict, reinstaller=False, callback=None, aio=False):
        super().__init__(callback, aio)
        self.__image = image
        self.__configuration = configuration
        self.__reinstaller = reinstaller

        self.facteur_throttle = 2.0

    def executer(self, docker_client: DockerClient, attendre=True):
        config_ajustee = self.__configuration.copy()
        del config_ajustee['image']

        if self.__reinstaller is True:
            nom_app = self.__configuration['name']
            try:
                service = docker_client.services.get(nom_app)
                service.remove()
            except APIError as apie:
                if apie.status_code == 404:
                    pass  # N'existe pas, OK
                else:
                    raise apie

        resultat = docker_client.services.create(self.__image, **config_ajustee)
        info_service = {'id': resultat.id, 'name': resultat.name}
        self.callback(info_service)

    async def get_resultat(self) -> list:
        resultat = await self.attendre()
        return resultat['args'][0]


class CommandeCreerSwarm(CommandeDocker):

    def __init__(self, callback=None, aio=False):
        super().__init__(callback, aio)

        self.facteur_throttle = 0.5

    def executer(self, docker_client: DockerClient, attendre=True):
        try:
            docker_client.swarm.init(advertise_addr="127.0.0.1")
        except APIError as apie:
            if apie.status_code == 409:
                pass  # OK, existe deja
            else:
                raise apie

        self.callback()


class CommandeCreerNetworkOverlay(CommandeDocker):

    def __init__(self, network_name: str, callback=None, aio=False):
        super().__init__(callback, aio)
        self.__network_name = network_name

        self.facteur_throttle = 0.5

    def executer(self, docker_client: DockerClient, attendre=True):
        try:
            docker_client.networks.create(name=self.__network_name, scope="swarm", driver="overlay", attachable=True)
        except APIError as apie:
            if apie.status_code == 409:
                pass  # OK, existe deja
            else:
                raise apie

        self.callback()


class CommandeGetImage(CommandeDocker):

    def __init__(self, nom_image: str, pull=False, callback=None, aio=False):
        super().__init__(callback, aio)
        self.__nom_image = nom_image
        self.__pull = pull
        self.pull_status = PullStatus()

        if pull is True:
            self.facteur_throttle = 1.0
        else:
            self.facteur_throttle = 0.5

    def executer(self, docker_client: DockerClient):
        try:
            reponse = docker_client.images.get(self.__nom_image)
            self.callback({'id': reponse.id, 'tags': reponse.tags})
            return
        except NotFound:
            pass

        if self.__pull is True:
            try:
                repository, nom_image_tag = self.__nom_image.split('/')
            except ValueError:
                repository = None
                nom_image_tag = self.__nom_image

            try:
                nom_image, tag = nom_image_tag.split(':')
            except ValueError:
                nom_image = nom_image_tag
                tag = None

            if nom_image is None:
                raise Exception("Nom image incorrect : %s" % self.__nom_image)

            if repository is not None:
                image_repository = '%s/%s' % (repository, nom_image)
            else:
                image_repository = nom_image

            try:
                # reponse = docker_client.images.pull(image_repository, tag)
                self.download_package(docker_client, image_repository, tag)
                reponse = docker_client.images.get(self.__nom_image)
                self.callback({'id': reponse.id, 'tags': reponse.tags})
                return
            except NotFound:
                pass

        self.callback(None)

    async def get_resultat(self) -> dict:
        resultat = await self.attendre()
        return resultat['args'][0]

    def download_package(self, client: docker.client.DockerClient, repository: str, tag: Optional[str] = None):
        pull_generator = client.api.pull(repository, tag, stream=True)
        layers = dict()
        for line in pull_generator:
            value = json.loads(line)

            try:
                status = value['status']
                layer_id = value['id']
            except KeyError:
                # Other status, like digest (all done)
                continue

            try:
                progress_detail = value['progressDetail']
            except KeyError:
                progress_detail = None

            if status == 'Downloading':
                try:
                    layers[layer_id].update(progress_detail)
                except KeyError:
                    layers[layer_id] = progress_detail
            elif status == 'Pull complete':
                layers[layer_id]['complete'] = True
            elif status == 'Already exists':
                layers[layer_id] = {'complete': True}
            elif status == 'Pulling fs layer':
                layers[layer_id] = {'complete': False, 'current': 0}

            self.pull_status.update(layers)
        self.pull_status.set_done()

    async def progress_coro(self):
        while self._event_asyncio.is_set() is False:
            status = self.pull_status.status_str()
            print("Downloading %s status: %s" % (self.__nom_image, status))
            try:
                await asyncio.wait_for(self._event_asyncio.wait(), 15)
            except asyncio.TimeoutError:
                pass
        print("Downloading %s status: Done" % self.__nom_image)

class PullStatus:

    def __init__(self):
        self.total_size = 0
        self.current_size = 0
        self.incomplete = 0
        self.all_totals_known = False
        self.pct = 0
        self.done = False

    def __dict__(self) -> dict:
        return {
            'total_size': self.total_size,
            'current_size': self.current_size,
            'incomplete': self.incomplete,
            'all_totals_known': self.all_totals_known,
            'pct': self.pct,
            'done': self.done,
        }

    def update(self, layers: dict[str, dict]):
        self.all_totals_known = True
        self.current_size = 0
        self.total_size = 0
        self.incomplete = 0
        for key, value in layers.items():
            if value.get('complete') is not True:
                self.incomplete = self.incomplete + 1
            try:
                self.total_size = self.total_size + value['total']
            except KeyError:
                if value.get('complete') is not True:
                    self.all_totals_known = False
            try:
                self.current_size = self.current_size + value['current']
            except KeyError:
                pass

        if self.all_totals_known and self.total_size > 0:
            # Calculer pct
            self.pct = math.floor(self.current_size / self.total_size * 100)

    def set_done(self):
        self.current_size = self.total_size
        self.incomplete = 0
        self.all_totals_known = True
        self.pct = 100
        self.done = True

    def status_str(self) -> str:
        if self.pct:
            return "Downloading: %d%% (%d/%d bytes), left to process: %d" % (self.pct, self.current_size, self.total_size, self.incomplete)
        else:
            return "Downloading: %d/%d+ bytes, left to process: %d" % (self.current_size, self.total_size, self.incomplete)


class CommandeEnsureNodeLabels(CommandeDocker):
    """
    S'assure de l'existence de labels dans la swarm. Creer le label sur le node de management sinon.
    """

    def __init__(self, labels: list, callback=None, aio=False):
        super().__init__(callback, aio)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__labels = labels
        self.facteur_throttle = 0.25

    def executer(self, docker_client: DockerClient, attendre=True):
        nodes = docker_client.nodes.list()

        labels_connus = set()
        for node in nodes:
            for label in node.attrs['Spec']['Labels']:
                labels_connus.add(label)

        node_create = nodes.pop()  # Choisir node random
        node_spec = node_create.attrs['Spec']
        labels = node_spec['Labels']
        node_name = node_create.attrs['Description']['Hostname']

        changement = False
        for label in self.__labels:
            if label not in labels_connus:
                self.__logger.debug("Ajouter label %s a node %s" % (label, node_name))
                labels[label] = 'true'
                changement = True

        if changement is True:
            node_create.update(node_spec)

        self.callback()


class CommandeGetConfigurationsDatees(CommandeDocker):
    """
    Fait la liste des config et secrets avec label certificat=true et password=true
    """
    def __init__(self, callback=None, aio=True):
        super().__init__(callback, aio)
        self.facteur_throttle = 0.5

    def executer(self, docker_client: DockerClient):

        dict_secrets = dict()
        dict_configs = dict()

        reponse = docker_client.secrets.list(filters={'label': 'certificat=true'})
        dict_secrets.update(self.parse_reponse(reponse))

        reponse = docker_client.secrets.list(filters={'label': 'password=true'})
        dict_secrets.update(self.parse_reponse(reponse))

        reponse = docker_client.configs.list(filters={'label': 'certificat=true'})
        dict_configs.update(self.parse_reponse(reponse))

        correspondance = self.correspondre_cle_cert(dict_secrets, dict_configs)

        self.callback({'configs': dict_configs, 'secrets': dict_secrets, 'correspondance': correspondance})

    def parse_reponse(self, reponse) -> dict:
        data = dict()

        for r in reponse:
            r_id = r.id
            name = r.name
            attrs = r.attrs
            labels = attrs['Spec']['Labels']
            data[name] = {'id': r_id, 'name': name, 'labels': labels}

        return data

    def correspondre_cle_cert(self, dict_secrets: dict, dict_configs: dict):

        dict_correspondance = dict()
        self.__mapper_params(dict_correspondance, list(dict_secrets.values()), 'key')
        self.__mapper_params(dict_correspondance, list(dict_configs.values()), 'cert')
        self.__mapper_params(dict_correspondance, list(dict_secrets.values()), 'password', label_type='password')

        # Ajouter key "current" pour chaque certificat
        for prefix, dict_dates in dict_correspondance.items():
            sorted_dates = sorted(dict_dates.keys(), reverse=True)
            for sdate in sorted_dates:
                contenu = dict_dates[sdate]
                try:
                    if contenu['cert'] is not None and contenu['key'] is not None:
                        dict_dates['current'] = contenu
                        break
                except KeyError:
                    pass
                try:
                    if contenu['password'] is not None:
                        dict_dates['current'] = contenu
                        break
                except KeyError:
                    pass

        return dict_correspondance

    def __mapper_params(self, dict_correspondance: dict, vals: list, key_param: str, label_type: str = 'certificat'):
        for v in vals:
            try:
                if v['labels'][label_type] == 'true':
                    prefix = v['labels']['label_prefix']
                    v_date = v['labels']['date']
                    try:
                        dict_prefix = dict_correspondance[prefix]
                    except KeyError:
                        dict_prefix = dict()
                        dict_correspondance[prefix] = dict_prefix

                    try:
                        dict_date = dict_prefix[v_date]
                    except KeyError:
                        dict_date = dict()
                        dict_prefix[v_date] = dict_date

                    dict_date[key_param] = {'name': v['name'], 'id': v['id']}
            except KeyError:
                pass  # Pas un certificat

    async def get_resultat(self) -> dict:
        resultat = await self.attendre()
        return resultat['args'][0]


class CommandeRunContainer(CommandeDocker):
    """
    Run une image dans un nouveau container
    """

    def __init__(self, image: str, command: Optional[str] = None, environment: Optional[dict] = None, mounts: Optional[list[docker.types.Mount]] = None):
        super().__init__(callback=None, aio=True)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__image = image
        self.__command = command
        self.__environment = environment
        self.__mounts = mounts

        self.facteur_throttle = 1.0

    def ajouter_mount(self, source: str, target: str, mount_type='volume', read_only=False):
        if self.__mounts is None:
            self.__mounts = list()
        mount = docker.types.Mount(target, source, type=mount_type, read_only=read_only)
        self.__mounts.append(mount)

    def executer(self, docker_client: DockerClient, attendre=True):
        params = {
            'environment': self.__environment,
            'mounts': self.__mounts,
            'network': 'millegrille_net',
            'auto_remove': True,
        }
        self.__logger.debug("Run %s %s" % (self.__image, self.__command))
        resultat = docker_client.containers.run(self.__image, command=self.__command, stdout=True, stderr=True, **params)
        self.callback(resultat)

    async def get_resultat(self) -> dict:
        resultat = await self.attendre()
        return resultat['args'][0]
