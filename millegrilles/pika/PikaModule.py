# Plug-in module pour pika 1.2 dans millegrilles messages
from millegrilles.messages.MessagesModule import MessagesModule


class PikaModule(MessagesModule):

    def __init__(self):
        super(MessagesModule, self).__init__()
        super(PikaModule, self).__init__()

