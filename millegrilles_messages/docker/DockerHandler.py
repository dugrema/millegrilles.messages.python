import asyncio
import docker
import logging
import json
import psutil

from asyncio import Event as EventAsyncio
from asyncio.events import AbstractEventLoop
from docker import DockerClient
from docker.errors import APIError, DockerException
from threading import Thread, Event
from typing import Optional


class DockerState:

    def __init__(self):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        path_socket = '/run/docker.sock'
        try:
            self.__docker = docker.DockerClient('unix://' + path_socket)
        except DockerException:
            self.__docker = None

        self.__logger.info("Docker socket a connecte %s" % path_socket)

        self.__docker_actif: Optional[bool] = None

    def docker_present(self):
        try:
            version_docker = self.__docker.version()
        except AttributeError:
            # __docker = None
            return False

        self.__logger.debug("Version docker : %s" % json.dumps(version_docker, indent=2))
        return True

    def swarm_present(self):
        try:
            info_docker = self.__docker.info()
        except AttributeError:
            return False  # __docker est None

        try:
            swarm_config = info_docker['Swarm']
            self.__logger.info("Information swarm docker %s" % json.dumps(swarm_config, indent=2))
            return swarm_config['Nodes'] > 0
        except KeyError:
            self.__logger.info("Swarm docker n'est pas configure")
            return False

    def docker_actif(self):
        if self.__docker_actif is None:
            try:
                present = self.docker_present()
                swarm = self.swarm_present()
                if present is True and swarm is True:
                    self.__docker_actif = True
                else:
                    self.__docker_actif = False
            except Exception:
                self.__logger.exception("Erreur verification etat docker")
                self.__docker_actif = False

        return self.__docker_actif

    @property
    def docker(self):
        return self.__docker


class CommandeDocker:

    def __init__(self, callback=None, aio=False):
        self.callback = callback

        self.__event_loop: Optional[AbstractEventLoop] = None
        self._event_asyncio: Optional[EventAsyncio] = None
        self.__resultat = None
        self.__is_error = False
        self.__exception = None

        self.facteur_throttle = 1.0  # Utilise pour throttling, represente un cout relatif de la commande

        if aio is True:
            self.__initasync()

    def executer(self, docker_client: DockerClient):
        if self.callback is not None:
            self.callback()

    def erreur(self, e: Exception):
        self.__is_error = True
        self.__exception = e
        if self.callback is not None:
            self.callback(e, is_error=True)

    def __callback_asyncio(self, *args, **argv):
        self.__resultat = {'args': args, 'argv': argv}
        self.__event_loop.call_soon_threadsafe(self._event_asyncio.set)

    def __initasync(self):
        self.__event_loop = asyncio.get_event_loop()
        self._event_asyncio = EventAsyncio()
        self.callback = self.__callback_asyncio

    async def attendre(self):
        if self._event_asyncio is not None:
            await self._event_asyncio.wait()

        if self.__is_error:
            raise self.__exception

        return self.__resultat


class DockerHandler:

    def __init__(self, docker_state: DockerState):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__docker = docker_state.docker

        self.__stop_event = Event()
        self.__action_pending = Event()
        self.__thread: Optional[Thread] = None
        self.__throttle_actions: Optional[float] = None

        self.__action_fifo = list()

        self.__docker_initialise = False

    def start(self):
        self.__thread = Thread(name="docker", target=self.run, daemon=True)
        self.__thread.start()

    def run(self):
        while self.__stop_event.is_set() is False:

            # Traiter actions
            while len(self.__action_fifo) > 0:
                action: CommandeDocker = self.__action_fifo.pop(0)
                self.__logger.debug("Traiter action docker %s" % action)
                try:
                    action.executer(self.__docker)
                except APIError as e:
                    # Monter silencieusement, erreur habituelle
                    action.erreur(e)
                except DockerHandlerException as e:
                    try:
                        # Bubble up sans logging
                        action.erreur(e)
                    except:
                        self.__logger.exception("Erreur emission action.erreur() commen reponse pour commande docker")
                except Exception as e:
                    self.__logger.exception("Erreur execution action docker")
                    try:
                        action.erreur(e)
                    except:
                        self.__logger.exception("Erreur emission action.erreur() commen reponse pour commande docker")
                    finally:
                        continue

                # Throttling commandes docker en fonction du CPU load
                # Sous 1.5 de load, aucun throttling. Apres, c'est 3*cpu_load jusqu'a limite de 30.0 secondes
                cpu_load, _cpu_load5, _cpu_load10 = psutil.getloadavg()
                cpu_load = max(cpu_load, 0.3)  # Fixer a au moins 0.3 pour creer un throttle sur chaque commande
                facteur_throttle = max(cpu_load, 0.3) * action.facteur_throttle
                wait_time = min(facteur_throttle, 30.0)  # Attendre load*n en secondes, max 30 secondes

                self.__logger.debug("Throttling commandes docker, cpu_load:%f attente %f secondes" % (cpu_load, wait_time))
                self.__stop_event.wait(wait_time)
                self.__logger.debug("Throttling commandes docker, pret pour prochaine commande")

                if self.__stop_event.is_set() is True:
                    return  # Abort thread

            self.__action_pending.wait(30)
            self.__action_pending.clear()

    def ajouter_commande(self, action: CommandeDocker):
        self.__action_fifo.append(action)
        self.__action_pending.set()


class DockerHandlerException(Exception):
    pass
