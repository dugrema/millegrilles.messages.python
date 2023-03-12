import logging
import datetime

from typing import Optional


class TacheEntretien:

    def __init__(self, intervalle: datetime.timedelta, callback, get_producer=None):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__intervalle = intervalle
        self.__callback = callback
        self.__dernier_entretien: Optional[datetime.datetime] = None
        self.__get_producer = get_producer

    def reset(self):
        """
        Force une execution a la prochaine occasion
        :return:
        """
        self.__dernier_entretien = None

    def set_intervalle(self, intervalle: datetime.timedelta):
        self.__intervalle = intervalle

    async def run(self):
        if self.__dernier_entretien is None:
            pass
        elif datetime.datetime.utcnow() - self.__intervalle > self.__dernier_entretien:
            pass
        else:
            return

        self.__dernier_entretien = datetime.datetime.utcnow()

        try:
            if self.__get_producer is not None:
                await self.__callback(self.__get_producer)
            else:
                await self.__callback()
        except:
            self.__logger.exception("Erreur execution tache entretien")
