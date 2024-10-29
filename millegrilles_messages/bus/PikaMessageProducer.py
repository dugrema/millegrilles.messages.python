import asyncio

from millegrilles_messages.bus.BusContext import MilleGrillesBusContext
from millegrilles_messages.bus.PikaChannel import MilleGrillesPikaChannel


class MilleGrillesPikaMessageProducer:

    def __init__(self, context: MilleGrillesBusContext, channel: MilleGrillesPikaChannel):
        self.__context = context
        self.__channel = channel

    async def ready(self):
        if self.__channel.ready.is_set() is False:
            await asyncio.wait_for(self.__channel.ready.wait(), 5)
        return self.__channel.ready.is_set()
