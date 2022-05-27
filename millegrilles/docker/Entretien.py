import logging
import datetime

from typing import Optional


class TacheEntretien:

    def __init__(self, intervalle: datetime.timedelta, callback):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__intervalle = intervalle
        self.__callback = callback
        self.__dernier_entretien: Optional[datetime.datetime] = None

    def reset(self):
        """
        Force une execution a la prochaine occasion
        :return:
        """
        self.__dernier_entretien = None

    async def run(self):
        if self.__dernier_entretien is None:
            pass
        elif datetime.datetime.utcnow() - self.__intervalle > self.__dernier_entretien:
            pass
        else:
            return

        self.__dernier_entretien = datetime.datetime.utcnow()

        try:
            await self.__callback()
        except:
            self.__logger.exception("Erreur execution tache entretien")