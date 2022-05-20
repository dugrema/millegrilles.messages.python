# Module de validation des certificats (X.509) et des messages avec _signature
import datetime
import json
import logging
import OpenSSL

from typing import Optional, Union

import redis.asyncio as redis

from millegrilles.messages.EnveloppeCertificat import EnveloppeCertificat


CACHE_TTL_SECS = 300
CACHE_MAX_ENTRIES = 100
REDIS_TTL_SECS = 48 * 60 * 60


class CertificatInconnu(Exception):

    def __init__(self, message, errors=None, fingerprint: str = None):
        super().__init__(message, errors)
        self.errors = errors
        self.__fingerprint = fingerprint

        try:
            self.__fingerprint.index(':')
        except ValueError:
            # Ajouter le type de hachage
            self.__fingerprint = self.__fingerprint
        except AttributeError:
            pass

    @property
    def fingerprint(self):
        return self.__fingerprint


class IdmgInvalide(Exception):
    pass


class ValidateurCertificat:
    """
    Validateur de base. Supporte uniquement la validation de chaine de certificats completes (en parametre).
    """

    def __init__(self, enveloppe_ca: EnveloppeCertificat):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__enveloppe_ca = enveloppe_ca

        self.__idmg = enveloppe_ca.idmg
        self.__store = OpenSSL.crypto.X509Store()

        certificat_millegrille_pem = enveloppe_ca.certificat_pem
        self.__root_cert_openssl = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                                                   certificat_millegrille_pem)
        self.__store.add_cert(self.__root_cert_openssl)

    def _charger_certificat(self, certificat: Union[bytes, str, list]) -> EnveloppeCertificat:
        if isinstance(certificat, list):
            certificat = ''.join(certificat)
        elif isinstance(certificat, (bytes, str)):
            pass
        else:
            raise TypeError("Type de certificat non supporte")

        return EnveloppeCertificat.from_pem(certificat)

    def valider(
            self,
            certificat: Union[bytes, str, list],
            date_reference: datetime.datetime = None,
            idmg: str = None,
            usages: set = {'digital_signature'}
    ) -> EnveloppeCertificat:
        """
        Valide un certificat.

        :param certificat: Un certificat ou une liste de certificats a valider.
        :param date_reference: Date de reference pour valider le certificat si autre que date courante.
        :param idmg: IDMG de la millegrille a valider (si autre que la millegrille locale).
        :param usages: Usages du certificat

        :return: Enveloppe avec le certificat valide.
        :raise OpenSSL.crypto.X509StoreContextError: Si la chaine de certificat est invalide.
        """
        enveloppe = self._charger_certificat(certificat)

        valide = self._valider(enveloppe, date_reference, idmg, usages)

        if valide:
            return enveloppe

        raise Exception('Erreur validation')  # Note : ne devrait pas arrive

    def _valider(self, enveloppe: EnveloppeCertificat, date_reference: datetime.datetime = None,
                  idmg: str = None, usages: set = {'digital_signature'}) -> bool:

        if idmg is not None and idmg != enveloppe.idmg:
            raise IdmgInvalide('IDMG invalide')

        try:
            if enveloppe.est_verifie and date_reference is None and (idmg is None or idmg == self.__idmg):
                # Raccourci, l'enveloppe a deja ete validee (e.g. cache) et on n'a aucune
                # validation conditionnelle par date ou idmg
                return True
        except AttributeError:
            pass  # Ok, le certificat n'est pas connu ou dans le cache

        store = self.__preparer_store(date_reference)

        chaine_pem = enveloppe.chaine_pem()

        chaine = [OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert) for cert in chaine_pem]
        cert = chaine.pop(0)

        store_ctx = OpenSSL.crypto.X509StoreContext(store, cert, chaine)
        try:
            store_ctx.verify_certificate()
        except OpenSSL.crypto.X509StoreContextError as ce:
            raise ce

        if date_reference is None and (idmg is None or idmg == self.__idmg):
            # Validation completee, certificat est valide (sinon OpenSSL.crypto.X509StoreContextError est lancee)
            enveloppe.set_est_verifie(True)

        return True

    def __preparer_store(self, date_reference: datetime.datetime = None) -> OpenSSL.crypto.X509Store:
        if date_reference is None:
            return self.__store
        else:
            # Creer store avec date de validation differente
            store = OpenSSL.crypto.X509Store()
            store.add_cert(self.__root_cert_openssl)
            store.set_time(date_reference)
            return store


class ValidateurCertificatCache(ValidateurCertificat):

    def __init__(self, enveloppe_ca: EnveloppeCertificat, cache_ttl_secs=CACHE_TTL_SECS):
        super().__init__(enveloppe_ca)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__cache_ttl_secs = cache_ttl_secs
        self.__cache_max_entries = CACHE_MAX_ENTRIES

        self.__cache_enveloppes = dict()

    async def valider(
            self,
            certificat: Union[bytes, str, list],
            date_reference: datetime.datetime = None,
            idmg: str = None,
            usages: set = {'digital_signature'}
    ) -> EnveloppeCertificat:

        enveloppe = super().valider(certificat, date_reference, idmg, usages)

        fingerprint = enveloppe.fingerprint
        try:
            cache_entry = self.__cache_enveloppes[fingerprint]
        except KeyError:
            if len(self.__cache_enveloppes) >= CACHE_MAX_ENTRIES:
                # Cache plein
                return enveloppe
            else:
                cache_entry = EnveloppeCache(enveloppe)
                self.__cache_enveloppes[fingerprint] = cache_entry

        if idmg is None and date_reference is None:
            # Valide pour date courante
            cache_entry.touch(presentement_valide=True)
        else:
            cache_entry.touch()

        return enveloppe

    async def valider_fingerprint(self, fingerprint: str, date_reference: datetime.datetime = None,
                                  idmg: str = None, usages: set = frozenset({'digital_signature'}),
                                  nofetch=False) -> EnveloppeCertificat:
        """
        Charge un certificat a partir du cache
        :return:
        """
        try:
            cache_entry = self.__cache_enveloppes[fingerprint]
        except KeyError:
            raise CertificatInconnu('CACHE MISS', fingerprint=fingerprint)

        if idmg is not None:
            if cache_entry.idmg != idmg:
                raise IdmgInvalide('IDMG invalide')

        enveloppe = cache_entry.enveloppe

        if cache_entry.valide is True and date_reference is None:
            cache_entry.touch()
            return enveloppe

        # Valider le certificat
        super()._valider(enveloppe, date_reference, idmg, usages)

    async def entretien(self):
        # Shallow copy pour eviter erreurs concurrence
        cache_copy = list(self.__cache_enveloppes.values())
        date_expiree = datetime.datetime.now() - datetime.timedelta(seconds=self.__cache_ttl_secs)
        for entry in cache_copy:
            if entry.date_activite < date_expiree:
                # Retirer entree
                try:
                    del self.__cache_enveloppes[entry.fingerprint]
                except KeyError:
                    pass


class EnveloppeCache:

    def __init__(self, enveloppe: EnveloppeCertificat):
        self.__enveloppe = enveloppe
        self.__fingerprint = enveloppe.fingerprint
        self.__idmg = enveloppe.idmg
        self.__date_activite = datetime.datetime.now()
        self.__presentement_valide: Optional[bool] = None

    def touch(self, presentement_valide: Optional[bool] = None):
        self.__date_activite = datetime.datetime.now()
        if presentement_valide is not None:
            self.__presentement_valide = presentement_valide

    @property
    def fingerprint(self) -> str:
        return self.__fingerprint

    @property
    def enveloppe(self) -> EnveloppeCertificat:
        return self.__enveloppe

    @property
    def idmg(self) -> str:
        return self.__idmg

    @property
    def valide(self) -> Optional[bool]:
        return self.__presentement_valide

    @property
    def date_activite(self):
        return self.__date_activite

    def __hash__(self):
        return hash(self.__fingerprint)

    def __eq__(self, other):
        return other.__fingerprint == self.__fingerprint


class ValidateurCertificatRedis(ValidateurCertificatCache):

    def __init__(self, enveloppe_ca: EnveloppeCertificat,
                 redis_hostname: str, redis_port: int, key_path: str, cert_path: str,
                 redis_username: str, redis_password: str,
                 cache_ttl_secs=CACHE_TTL_SECS):
        super().__init__(enveloppe_ca, cache_ttl_secs)

        self.__enveloppe_ca = enveloppe_ca
        self.__redis_hostname = redis_hostname
        self.__redis_port = redis_port
        self.__cert_path = cert_path
        self.__key_path = key_path
        self.__redis_username = redis_username
        self.__redis_password = redis_password

        self.__redis_client: Optional[redis.Redis] = None

    async def __connecter(self):
        if self.__redis_client is None:
            ca_pem = self.__enveloppe_ca.certificat_pem
            client = redis.Redis(host=self.__redis_hostname, port=self.__redis_port,
                                 username=self.__redis_username, password=self.__redis_password,
                                 ssl=True, ssl_keyfile=self.__key_path, ssl_certfile=self.__cert_path,
                                 ssl_ca_data=ca_pem)
            self.__redis_client = client

        await self.__redis_client.ping()

    async def entretien(self):
        await super().entretien()
        await self.__connecter()

    async def __get_certficat(self, fingerprint) -> list:
        if self.__redis_client is None:
            raise CertificatInconnu('CONNEXION FERMEE', fingerprint=fingerprint)

        cert_data = await self.__redis_client.getex('certificat_v1:%s' % fingerprint, REDIS_TTL_SECS)

        if cert_data is None:
            raise CertificatInconnu('PERSISTENT CACHE MISS', fingerprint=fingerprint)

        # Parse json, format {"pems": [], "ca": ""}
        cert_dict = json.loads(cert_data)
        return cert_dict['pems']

    async def valider_fingerprint(self, fingerprint: str, date_reference: datetime.datetime = None,
                                  idmg: str = None, usages: set = frozenset({'digital_signature'}),
                                  nofetch=False) -> EnveloppeCertificat:

        try:
            return await super().valider_fingerprint(fingerprint, date_reference, idmg, usages, nofetch)
        except CertificatInconnu as ci:
            pems = await self.__get_certficat(fingerprint)
            return await self.valider(pems, date_reference, idmg, usages)
