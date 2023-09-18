# Connexion a MQ et gestion messages
import asyncio
import logging
import os

from asyncio import Event, TimeoutError
from typing import Optional

from millegrilles_messages.messages import Constantes
from millegrilles_messages.messages.MessagesModule import RessourcesConsommation, MessageWrapper
from millegrilles_messages.messages.MessagesThread import MessagesThread
from millegrilles_messages.messages.CleCertificat import CleCertificat
from millegrilles_messages.messages.EnveloppeCertificat import EnveloppeCertificat
from millegrilles_messages.messages.FormatteurMessages import SignateurTransactionSimple, FormatteurMessageMilleGrilles
from millegrilles_messages.messages.ValidateurCertificats import ValidateurCertificatCache, CertificatInconnu
from millegrilles_messages.messages.ValidateurMessage import ValidateurMessage
from millegrilles_messages.messages.MessagesModule import MessageProducerFormatteur

from millegrilles_messages.messages import Constantes as ConstantesMessages

CONST_PARAMS = [
    ConstantesMessages.ENV_CA_PEM,
    ConstantesMessages.ENV_CERT_PEM,
    ConstantesMessages.ENV_KEY_PEM,
    ConstantesMessages.ENV_MQ_HOSTNAME,
    ConstantesMessages.ENV_MQ_PORT,
]


class Configuration:
    """
    Implementer cette classe pour ajouter des parametres de configuration.
    """

    def __init__(self):
        self.cert_pem_path: Optional[str] = None
        self.key_pem_path: Optional[str] = None
        self.ca_pem_path = '/var/opt/millegrilles/configuration/pki.millegrille.cert'
        self.mq_host = 'mq'
        self.mq_port = 5673

    def get_params_list(self) -> list:
        return CONST_PARAMS

    def get_env(self) -> dict:
        """
        Extrait l'information pertinente de os.environ
        :return: Configuration dict
        """
        config = dict()
        for opt_param in self.get_params_list():
            value = os.environ.get(opt_param)
            if value is not None:
                config[opt_param] = value

        return config

    def parse_config(self, configuration: Optional[dict] = None) -> dict:
        """
        Conserver l'information de configuration
        :param configuration:
        :return:
        """
        dict_params = self.get_env()
        if configuration is not None:
            dict_params.update(configuration)

        # Parametres obligatoires
        self.cert_pem_path = dict_params[ConstantesMessages.ENV_CERT_PEM]
        self.key_pem_path = dict_params[ConstantesMessages.ENV_KEY_PEM]

        # Parametres optionnels / overrides
        self.ca_pem_path = dict_params.get(ConstantesMessages.ENV_CA_PEM) or self.ca_pem_path
        self.mq_host = dict_params.get(ConstantesMessages.ENV_MQ_HOSTNAME) or self.mq_host
        self.mq_port = dict_params.get(ConstantesMessages.ENV_MQ_PORT) or self.mq_port

        return dict_params


class EtatInstance:
    """
    Objet qui contient la configuration et autre information d'etat (incluant producer).
    """

    def __init__(self, configuration: Configuration = None):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        if configuration is None:
            # Aucune configuration custom, charger les parametres d'environnements
            configuration = Configuration()

        self.__configuration = configuration

        self.__configuration_json: Optional[dict] = None

        self.__instance_id: Optional[str] = None
        self.__mq_host: Optional[str] = None
        self.__mq_port: Optional[int] = None
        self.__clecertificat: Optional[CleCertificat] = None
        self.__certificat_millegrille: Optional[EnveloppeCertificat] = None

        self.__listeners_actions = list()

        self.__formatteur_message: Optional[FormatteurMessageMilleGrilles] = None
        self.__validateur_certificats: Optional[ValidateurCertificatCache] = None
        self.__validateur_message: Optional[ValidateurMessage] = None

        self.__producer: Optional[MessageProducerFormatteur] = None
        self.__partition: Optional[str] = None

        self.__backup_inhibe = False

    async def reload_configuration(self):
        self.__logger.info("Reload configuration sur disque ou dans docker")

        self.__mq_host = self.__configuration.mq_host or self.__configuration_json.get('mq_host') or 'mq'
        self.__mq_port = self.__configuration.mq_port or self.__configuration_json.get('mq_port') or 5673

        self.__certificat_millegrille = EnveloppeCertificat.from_file(self.__configuration.ca_pem_path)
        self.__validateur_certificats = ValidateurCertificatCache(self.__certificat_millegrille)

        # Charger et verificat cle/certificat
        self.__clecertificat = CleCertificat.from_files(
            self.__configuration.key_pem_path, self.__configuration.cert_pem_path)

        if self.__clecertificat is not None:
            idmg = self.__clecertificat.enveloppe.idmg

            # Valider le certificat en memoire
            try:
                await self.__validateur_certificats.valider(self.__clecertificat.enveloppe.chaine_pem())

                signateur = SignateurTransactionSimple(self.__clecertificat)
                self.__formatteur_message = FormatteurMessageMilleGrilles(idmg, signateur)
                self.__validateur_message = ValidateurMessage(self.__validateur_certificats)
            except Exception:
                self.__logger.exception("Certificat invalide/expire")
                self.__formatteur_message = None
                self.__validateur_message = None

        for listener in self.__listeners_actions:
            await listener()

    async def run(self, stop_event, rabbitmq_dao):
        while stop_event.is_set() is False:

            # Taches entretien
            await self.entretien(rabbitmq_dao)

            try:
                await asyncio.wait_for(stop_event.wait(), timeout=30)
            except asyncio.TimeoutError:
                pass  # OK

    async def entretien(self, rabbitmq_dao):
        pass

    def ajouter_listener(self, listener):
        self.__listeners_actions.append(listener)

    async def fermer(self):
        for listener in self.__listeners_actions:
            await listener(fermer=True)

    async def verifier_certificat_expire(self):
        enveloppe = self.clecertificat.enveloppe
        try:
            enveloppe = await self.__validateur_certificats.valider(enveloppe.chaine_pem())
            return enveloppe is None
        except:
            self.__logger.warning("Le certificat local est expire")
            return True

    async def charger_certificat(self, fingerprint: str):
        """ Charge un certificat a partir de son fingerprint """
        try:
            return await self.__validateur_certificats.valider_fingerprint(fingerprint)
        except CertificatInconnu as ce:
            # Tenter de charger a partir de MQ
            producer = self.producer
            if producer is not None:
                await asyncio.wait_for(producer.producer_pret().wait(), 1)
                self.__validateur_certificats.set_producer_messages(producer)
                cert_pems = await self.__validateur_certificats.fetch_certificat(fingerprint)
                enveloppe = await self.__validateur_certificats.valider(cert_pems)
                return enveloppe

            # Echec de chargement
            raise ce

    @property
    def configuration(self) -> Configuration:
        return self.__configuration

    @property
    def clecertificat(self):
        return self.__clecertificat

    @property
    def instance_id(self):
        return self.__instance_id

    @property
    def mq_host(self):
        return self.__mq_host

    @property
    def mq_port(self):
        return self.__mq_port

    def set_producer(self, producer: MessageProducerFormatteur):
        self.__producer = producer

    @property
    def producer(self):
        return self.__producer

    def set_partition(self, partition: str):
        self.__partition = partition

    @property
    def partition(self):
        return self.__partition

    @property
    def formatteur_message(self):
        return self.__formatteur_message

    @property
    def backup_inhibe(self):
        return self.__backup_inhibe

    @backup_inhibe.setter
    def backup_inhibe(self, value):
        self.__backup_inhibe = value

    @property
    def validateur_message(self):
        return self.__validateur_message


class CommandHandler:
    """
    Implementer la methode traiter_commande de cette classe pour recevoir les messages d'une Q.
    """

    def __init__(self):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def get_routing_keys(self) -> list:
        # Retourner une liste de routing keys a mettre sur la Q de reponse volatile
        # Ex : return ['evenement.GrosFichiers.*.jobImageDisponible', 'evenement.GrosFichiers.annulerJobVideo']
        raise NotImplementedError('Non implemente')

    def configurer_consumers(self, messages_thread):
        raise NotImplementedError("Non implemente")

    async def executer_commande(self, producer: MessageProducerFormatteur, message: MessageWrapper):
        routing_key = message.routing_key
        exchange = message.exchange
        if exchange is None or exchange == '':
            self.__logger.warning("Message reponse recu sur Q commande, on le drop (RK: %s)" % routing_key)
            return

        if message.est_valide is False:
            return {'ok': False, 'err': 'Signature ou certificat invalide'}

        try:
            reponse = await self.traiter_commande(producer, message)

            if reponse is False:
                reponse = None  # Ne rien retourner
            elif reponse is None:
                self.__logger.warning("Commande inconnue ou acces refuse : %s" % routing_key)
                reponse = {'ok': False, 'err': 'Commande inconnue ou acces refuse'}

        except Exception as e:
            self.__logger.exception("Erreur execution commande")
            reponse = {'ok': False, 'err': str(e)}

        return reponse

    async def traiter_commande(self, producer: MessageProducerFormatteur, message: MessageWrapper):
        # Note : implementer pour traiter la commande

        # Exemple d'information utile a extraire

        # from cryptography.x509.extensions import ExtensionNotFound
        # action = routing_key.split('.').pop()
        # type_message = routing_key.split('.')[0]
        # enveloppe = message.certificat
        #
        # try:
        #     exchanges = enveloppe.get_exchanges
        # except ExtensionNotFound:
        #     exchanges = list()
        #
        # try:
        #     user_id = enveloppe.get_user_id
        # except ExtensionNotFound:
        #     user_id = list()
        #
        # try:
        #     delegation_globale = enveloppe.get_delegation_globale
        # except ExtensionNotFound:
        #     delegation_globale = None

        raise NotImplementedError("Non implemente")

    async def callback_reply_q(self, message: MessageWrapper, module_messages: MessagesThread):
        self.__logger.debug("RabbitMQ nessage recu : %s" % message)
        producer = module_messages.get_producer()
        reponse = await self.executer_commande(producer, message)

        if reponse is not None:
            reply_to = message.reply_to
            correlation_id = message.correlation_id
            await producer.repondre(reponse, reply_to, correlation_id)


class MqThread:
    """
    Thread d'execution MQ. Utiliser via instance de RabbitMQDao.
    """

    def __init__(self, event_stop: Event, etat_instance: EtatInstance,
                 command_handler: CommandHandler, routing_keys_consumers: list):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__event_stop = event_stop
        self.__etat_instance = etat_instance
        self.__command_handler = command_handler
        self.__routing_key_consumers = routing_keys_consumers

        self.__mq_host: Optional[str] = None
        self.__mq_port: Optional[str] = None
        self.__messages_thread: Optional[MessagesThread] = None
        self.__event_producer: Optional[Event] = None

    async def configurer(self):
        self.__mq_host = self.__etat_instance.mq_host
        self.__mq_port = self.__etat_instance.mq_port

        env_configuration = {
            Constantes.ENV_CA_PEM: self.__etat_instance.configuration.ca_pem_path,
            Constantes.ENV_CERT_PEM: self.__etat_instance.configuration.cert_pem_path,
            Constantes.ENV_KEY_PEM: self.__etat_instance.configuration.key_pem_path,
            Constantes.ENV_MQ_HOSTNAME: self.__mq_host,
            Constantes.ENV_MQ_PORT: self.__mq_port,
        }

        self.__messages_thread = self.creer_ressources_consommation(env_configuration)
        await self.__messages_thread.start_async()  # Preparer le reste de l'environnement

    def creer_ressources_consommation(self, env_configuration: dict) -> MessagesThread:
        messages_thread = MessagesThread(self.__event_stop)
        messages_thread.set_env_configuration(env_configuration)

        reply_res = RessourcesConsommation(self.callback_reply_q)

        # RK Public pour toutes les instances
        for rk in self.__routing_key_consumers:
            reply_res.ajouter_rk(Constantes.SECURITE_PRIVE, rk)

        messages_thread.set_reply_ressources(reply_res)

        self.__command_handler.configurer_consumers(messages_thread)

        return messages_thread

    async def run(self):
        # coroutine principale d'execution MQ
        await self.__messages_thread.run_async()

    async def callback_reply_q(self, message: MessageWrapper, module_messages):
        self.__logger.debug("RabbitMQ nessage recu : %s" % message)
        producer = self.__messages_thread.get_producer()
        reponse = await self.__command_handler.executer_commande(producer, message)

        if reponse is not None:
            reply_to = message.reply_to
            correlation_id = message.correlation_id
            producer = self.__messages_thread.get_producer()
            await producer.repondre(reponse, reply_to, correlation_id)

    def get_producer(self) -> Optional[MessageProducerFormatteur]:
        try:
            return self.__messages_thread.get_producer()
        except AttributeError:
            # Thread inactive
            return None

    async def attendre_pret(self, timeout=30):
        if self.__messages_thread is not None:
            await self.__messages_thread.attendre_pret(timeout)
            return True
        else:
            return False

    async def start_consumer(self, nom_q: str):
        await self.__messages_thread.start_consumer(nom_q)

    async def stop_consumer(self, nom_q: str):
        await self.__messages_thread.stop_consumer(nom_q)


class MilleGrillesConnecteur:
    """
    Creer une instance de cette classe pour obtenir une connexion a la MilleGrille.
    """

    def __init__(self, event_stop: Event, etat_instance: EtatInstance, command_handler: CommandHandler):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__event_stop = event_stop
        self.__etat_instance = etat_instance

        self.__command_handler = command_handler

        self.__producer: Optional[MessageProducerFormatteur] = None
        self.__mq_thread: Optional[MqThread] = None

    async def __creer_thread(self):
        routing_keys = self.__command_handler.get_routing_keys()
        return MqThread(self.__event_stop, self.__etat_instance, self.__command_handler, routing_keys)

    def get_producer(self) -> Optional[MessageProducerFormatteur]:
        return self.__producer

    async def run(self):
        self.__logger.info("Debut thread asyncio MessagesThread")

        try:
            # Toujours tenter de creer le compte sur MQ - la detection n'est pas au point a l'interne
            resultat_creer_compte = await self.creer_compte_mq()
            self.__logger.info("Resultat creer compte MQ : %s" % resultat_creer_compte)

            # coroutine principale d'execution MQ
            self.__mq_thread = await self.__creer_thread()
            await self.__mq_thread.configurer()
            self.__producer = self.__mq_thread.get_producer()
            self.__etat_instance.set_producer(self.__producer)  # Hook producer globalement

            await self.__mq_thread.run()
        except Exception as e:
            self.__logger.exception("Erreur connexion MQ")
        finally:
            self.__mq_thread = None
            self.__producer = None
            self.__etat_instance.set_producer(None)  # Cleanup hook producer globalement

        self.__logger.info("Fin thread MessagesThread")

    async def creer_compte_mq(self):
        """
        Creer un compte sur MQ via https (midcompte).
        :return:
        """
        mq_host = self.__etat_instance.mq_host
        self.__logger.info("Creation compte MQ avec %s" % mq_host)

        # Le monitor peut etre trouve via quelques hostnames :
        #  nginx : de l'interne, est le proxy web qui est mappe vers le monitor
        #  mq_host : de l'exterieur, est le serveur mq qui est sur le meme swarm docker que nginx
        hosts = ['nginx', self.__etat_instance.mq_host]
        port = 444  # 443
        path = 'administration/ajouterCompte'

        mq_cafile = self.__etat_instance.configuration.ca_pem_path
        mq_certfile = self.__etat_instance.configuration.cert_pem_path
        mq_keyfile = self.__etat_instance.configuration.key_pem_path

        with open(mq_certfile, 'r') as fichier:
            chaine_cert = {'certificat': fichier.read()}

        cle_cert = (mq_certfile, mq_keyfile)
        self.__logger.debug("Creation compte MQ avec fichiers %s" % str(cle_cert))
        try:
            import requests
            for host in hosts:
                path_complet = 'https://%s:%d/%s' % (host, port, path)
                try:
                    self.__logger.debug("Creation compte avec path %s" % path_complet)
                    reponse = requests.post(path_complet, json=chaine_cert, cert=cle_cert, verify=mq_cafile)
                    if reponse.status_code in [200, 201]:
                        return True
                    else:
                        self.__logger.error("Erreur creation compte MQ via https, code : %d", reponse.status_code)
                except requests.exceptions.SSLError as e:
                    self.__logger.exception("Erreur connexion https pour compte MQ")
                except requests.exceptions.ConnectionError:
                    # Erreur connexion au serveur, tenter le prochain host
                    self.__logger.info("Echec creation compte MQ avec %s" % path_complet)
        except ImportError:
            self.__logger.warning("requests non disponible, on ne peut pas tenter d'ajouter le compte MQ")
            requests = None

        return False

    async def attendre_pret(self, timeout=30) -> bool:
        """
        Utiliser cette methode pour s'assurer que la connexion a MQ est prete.
        :param timeout:
        :return:
        """
        if self.__mq_thread is not None:
            return await self.__mq_thread.attendre_pret(timeout)
        else:
            return False

    @property
    def mq_thread(self) -> Optional[MqThread]:
        return self.__mq_thread
