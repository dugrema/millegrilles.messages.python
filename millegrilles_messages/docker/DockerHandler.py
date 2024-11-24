import asyncio
import docker
import logging
import json
import psutil

from asyncio import Event as EventAsyncio, TaskGroup
from asyncio.events import AbstractEventLoop
from docker import DockerClient
from docker.errors import APIError, DockerException
from typing import Optional

from millegrilles_messages.bus.BusContext import MilleGrillesBusContext


class DockerState:

    def __init__(self, context: MilleGrillesBusContext):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__context = context
        path_socket = '/run/docker.sock'
        try:
            self.__docker = docker.DockerClient('unix://' + path_socket)
        except DockerException:
            self.__docker = None

        self.__logger.info("Docker socket a connecte %s" % path_socket)

        self.__docker_actif: Optional[bool] = None

    @property
    def context(self) -> MilleGrillesBusContext:
        return self.__context

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
        self.__context = docker_state.context
        self.__docker = docker_state.docker
        self.__action_fifo: asyncio.Queue[Optional[CommandeDocker]] = asyncio.Queue(maxsize=10)

    @property
    def context(self) -> MilleGrillesBusContext:
        return self.__context

    async def run(self):
        async with TaskGroup() as group:
            group.create_task(self.__process_actions())

    async def __stop_thread(self):
        await self.context.wait()
        await self.__action_fifo.put(None)  # Stop condition

    async def ajouter_commande(self, action: CommandeDocker):
        await self.__action_fifo.put(action)

    async def __process_actions(self):
        while self.context.stopping is False:
            action = await self.__action_fifo.get()
            if action is None or self.context.stopping is True:
                return  # Stop condition

            self.__logger.debug("Traiter action docker %s" % action)
            try:
                await asyncio.to_thread(action.executer, self.__docker)
            except APIError as e:
                # Monter silencieusement, erreur habituelle
                action.erreur(e)
            except DockerHandlerException as e:
                try:
                    # Bubble up sans logging
                    await asyncio.to_thread(action.erreur, e)
                except:
                    self.__logger.exception("Erreur emission action.erreur() commen reponse pour commande docker")
            except Exception as e:
                self.__logger.exception("Erreur execution action docker")
                try:
                    await asyncio.to_thread(action.erreur, e)
                except:
                    self.__logger.exception("Erreur emission action.erreur() commen reponse pour commande docker")
                finally:
                    continue

            # Throttling commandes docker en fonction du CPU load
            cpu_load, _cpu_load5, _cpu_load10 = await asyncio.to_thread(psutil.getloadavg)
            cpu_load = max(cpu_load, 0.3)  # Fixer a au moins 0.3 pour creer un throttle sur chaque commande
            facteur_throttle = max(cpu_load, 0.3) * action.facteur_throttle
            wait_time = min(facteur_throttle, 30.0)  # Attendre load*n en secondes, max 30 secondes

            self.__logger.debug("Throttling commandes docker, cpu_load:%f attente %f secondes" % (cpu_load, wait_time))
            await self.context.wait(wait_time)
            self.__logger.debug("Throttling commandes docker, pret pour prochaine commande")


class DockerHandlerException(Exception):
    pass
