# Template pour intake de jobs via Q
import logging

from typing import Optional

from asyncio import Event, TimeoutError, wait, FIRST_COMPLETED

from millegrilles_messages.MilleGrillesConnecteur import EtatInstance


class IntakeHandler:

    def __init__(self, stop_event: Event, etat_instance: EtatInstance, timeout_cycle: Optional[int] = None):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self._etat_instance = etat_instance
        self._timeout_cycle = timeout_cycle
        self.__event_intake: Optional[Event] = None
        self.__stop_event = stop_event

    async def configurer(self):
        self.__event_intake = Event()

    async def trigger_traitement(self):
        self.__logger.info('IntakeHandler trigger intake recu')
        self.__event_intake.set()

    async def run(self):
        self.__logger.info('IntakeHandler running')
        while not self.__stop_event.is_set():
            try:
                if self.__event_intake.is_set() is False:
                    await wait(
                        [self.__stop_event.wait(), self.__event_intake.wait()],
                        timeout=self._timeout_cycle, return_when=FIRST_COMPLETED
                    )
                    self.__event_intake.set()
            except TimeoutError:
                self.__logger.debug("run Verifier si fichier disponible pour indexation")
                self.__event_intake.set()

            if self.__stop_event.is_set():
                self.__logger.info('run Arret loop traiter_fichiers')
                break

            try:
                # Requete prochain fichier
                job_done = await self.traiter_prochaine_job()
                if job_done is None:
                    # On a termine les jobs disponible, boucler et attendre
                    self.__event_intake.clear()
            except Exception as e:
                self.__logger.exception("run Erreur traitement : %s" % e)
                # Erreur generique non geree. Creer un delai de traitement pour poursuivre
                self.__event_intake.clear()

    async def traiter_prochaine_job(self) -> dict:
        raise NotImplementedError('must override')

    async def annuler_job(self, job: dict, emettre_evenement=False):
        raise NotImplementedError('must override')
