# Module de validation des certificats (X.509) et des messages avec _signature
import datetime
import logging
import OpenSSL

from typing import Optional, Union

from cryptography.x509.base import Certificate

from millegrilles.messages.EnveloppeCertificat import EnveloppeCertificat


class CertificatInconnu(Exception):

    def __init__(self, message, errors =None, fingerprint: str = None):
        super().__init__(message, errors)
        self.errors = errors
        self.__fingerprint = fingerprint

        try:
            self.__fingerprint.index(':')
        except ValueError:
            # Ajouter le type de hachage
            self.__fingerprint = self.__fingerprint

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
        print(certificat_millegrille_pem)
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

        if idmg is not None and idmg != enveloppe.idmg:
            raise IdmgInvalide('IDMG invalide')

        try:
            if enveloppe.est_verifie and date_reference is None and (idmg is None or idmg == self.__idmg):
                # Raccourci, l'enveloppe a deja ete validee (e.g. cache) et on n'a aucune
                # validation conditionnelle par date ou idmg
                return enveloppe
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

        # La chaine est valide (potentiellement avec conditions comme idmg ou date_reference)
        self._conserver_enveloppe(enveloppe)

        return enveloppe

    def __preparer_store(self, date_reference: datetime.datetime = None) -> OpenSSL.crypto.X509Store:
        if date_reference is None:
            return self.__store
        else:
            # Creer store avec date de validation differente
            store = OpenSSL.crypto.X509Store()
            store.add_cert(self.__root_cert_openssl)
            store.set_time(date_reference)
            return store

    def _conserver_enveloppe(self, enveloppe: EnveloppeCertificat):
        """
        Hook pour sous-classes (e.g. caching)
        :param enveloppe:
        :return:
        """
        pass
