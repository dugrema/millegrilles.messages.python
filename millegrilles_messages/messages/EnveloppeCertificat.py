# Utilitaires pour les certificats X.509

import base58
import base64
import binascii
import datetime
import logging
import math
import struct
import pytz

from typing import Optional, Union

import multibase
import multihash

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_pem_x509_certificate, ObjectIdentifier, NameOID, SubjectKeyIdentifier, \
    AuthorityKeyIdentifier, BasicConstraints
from cryptography.x509.base import Certificate
from cryptography.x509.extensions import ExtensionNotFound
from multihash.constants import HASH_CODES
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from nacl.signing import VerifyKey

from millegrilles_messages.messages.Hachage import hacher, map_code_to_hashes
from millegrilles_messages.messages.Ed25519Utils import chiffrer_cle_ed25519

BEGIN_CERTIFICATE = '-----BEGIN CERTIFICATE-----'
END_CERTIFICATE = '-----END CERTIFICATE-----'


class EnveloppeCertificat:
    """ Encapsule un certificat. """

    ENCODING_FINGERPRINT = 'base58btc'
    HASH_FINGERPRINT = 'blake2s-256'

    def __init__(self, certificat: Certificate, pems: Union[str, bytes, list]):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__certificat = certificat

        self.__est_verifie = False  # Flag qui est change une fois la chaine verifiee
        self.__chaine_pem = preparer_chaine_certificats(pems)  # Chaine certificats, moins root
        self.__millegrille_pem: Optional[str] = None  # PEM du certificat de la millegrille

        self.__fingerprint = calculer_fingerprint(certificat)
        self.__pubkey_str = None
        self.__idmg = trouver_idmg(self)

    @staticmethod
    def from_pem(pem: Union[str, bytes, list]):
        if isinstance(pem, str):
            pem = pem.encode('utf-8')
        elif isinstance(pem, list):
            pem = '\n'.join(pem).encode('utf-8')
        certificat = load_pem_x509_certificate(pem, backend=default_backend())
        enveloppe = EnveloppeCertificat(certificat, pem)
        return enveloppe

    @staticmethod
    def from_certificate(certificat: Certificate, intermediaires_pem: Optional[list] = None):
        pem_certificat = str(certificat.public_bytes(serialization.Encoding.PEM), 'utf-8')
        chaine_pems = [pem_certificat]
        if intermediaires_pem is not None:
            chaine_pems.extend(intermediaires_pem)
        enveloppe = EnveloppeCertificat(certificat, chaine_pems)
        return enveloppe

    @staticmethod
    def from_file(file_path: str):
        with open(file_path, 'r') as fichier:
            pem = fichier.read()
        return EnveloppeCertificat.from_pem(pem)

    @property
    def fingerprint(self) -> str:
        if self.is_ed25519():
            if self.__pubkey_str is None:
                self.__pubkey_str = binascii.hexlify(self.get_public_key_bytes()).decode('utf-8')
            return self.__pubkey_str
        else:
            return self.__fingerprint

    @property
    def idmg(self) -> str:
        """
        Retourne le idmg du certificat.
        """
        if self.__idmg is None:
            # Verifier si cert est root CA
            if self.is_root_ca:
                # Calculer IDMG
                self.__idmg = encoder_idmg_cert(self.__certificat)
            else:
                # Utiliser SKID Organization
                self.__idmg = self.subject_organization_name

        return self.__idmg

    @property
    def certificat(self) -> Certificate:
        return self.__certificat

    @property
    def certificat_pem(self):
        if self.__chaine_pem is not None:
            return self.__chaine_pem[0]

        return str(self.certificat.public_bytes(serialization.Encoding.PEM), 'utf-8')

    def get_public_key(self):
        return self.certificat.public_key()

    def get_public_key_bytes(self):
        return self.certificat.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

    def public_key_str(self):
        public_key = self.certificat.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        public_key_str = str(public_key, 'utf-8')
        return public_key_str

    @property
    def get_roles(self):
        MQ_ROLES_OID = ObjectIdentifier('1.2.3.4.1')
        extensions = self.__certificat.extensions
        oid_attribute = extensions.get_extension_for_oid(MQ_ROLES_OID)
        oid_value = oid_attribute.value
        oid_value = oid_value.value.decode('utf-8')
        attribute_values = oid_value.split(',')
        return attribute_values

    @property
    def get_exchanges(self):
        MQ_EXCHANGES_OID = ObjectIdentifier('1.2.3.4.0')
        extensions = self.__certificat.extensions
        oid_attribute = extensions.get_extension_for_oid(MQ_EXCHANGES_OID)
        oid_value = oid_attribute.value
        oid_value = oid_value.value.decode('utf-8')
        attribute_values = oid_value.split(',')
        return attribute_values

    @property
    def get_domaines(self):
        MQ_DOMAINES_OID = ObjectIdentifier('1.2.3.4.2')
        extensions = self.__certificat.extensions
        oid_attribute = extensions.get_extension_for_oid(MQ_DOMAINES_OID)
        oid_value = oid_attribute.value
        oid_value = oid_value.value.decode('utf-8')
        attribute_values = oid_value.split(',')
        return attribute_values

    @property
    def get_user_id(self) -> str:
        MQ_USERID_OID = ObjectIdentifier('1.2.3.4.3')
        extensions = self.__certificat.extensions
        oid_attribute = extensions.get_extension_for_oid(MQ_USERID_OID)
        oid_value = oid_attribute.value
        oid_value = oid_value.value.decode('utf-8')
        return oid_value

    @property
    def get_delegation_globale(self) -> str:
        MQ_DELEGATION_GLOBALE_OID = ObjectIdentifier('1.2.3.4.4')
        extensions = self.__certificat.extensions
        oid_attribute = extensions.get_extension_for_oid(MQ_DELEGATION_GLOBALE_OID)
        oid_value = oid_attribute.value
        oid_value = oid_value.value.decode('utf-8')
        return oid_value

    @property
    def get_delegations_domaines(self) -> list:
        MQ_DOMAINES_OID = ObjectIdentifier('1.2.3.4.5')
        extensions = self.__certificat.extensions
        oid_attribute = extensions.get_extension_for_oid(MQ_DOMAINES_OID)
        oid_value = oid_attribute.value
        oid_value = oid_value.value.decode('utf-8')
        attribute_values = oid_value.split(',')
        return attribute_values

    @property
    def subject_organization_name(self):
        organization = self.__certificat.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        if len(organization) > 0:
            return organization[0].value
        return None

    @property
    def subject_organizational_unit_name(self):
        org = self.__certificat.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
        if org is not None and len(org) > 0:
            return org[0].value
        return None

    @property
    def subject_common_name(self):
        sujet = self.certificat.subject
        cn = sujet.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        return cn

    @property
    def not_valid_before(self) -> datetime.datetime:
        # Note : utilisation de pytz pour transformer la date vers le format datetime python3
        #        cryptography utilise un format susceptible a epochalypse sur .timestamp()
        #        https://en.wikipedia.org/wiki/Year_2038_problem
        return pytz.utc.localize(self.__certificat.not_valid_before)

    @property
    def not_valid_after(self) -> datetime.datetime:
        # Note : utilisation de pytz pour transformer la date vers le format datetime python3
        #        cryptography utilise un format susceptible a epochalypse sur .timestamp()
        #        https://en.wikipedia.org/wiki/Year_2038_problem
        return pytz.utc.localize(self.__certificat.not_valid_after)

    @property
    def subject_key_identifier(self):
        subjectKeyIdentifier = self.__certificat.extensions.get_extension_for_class(SubjectKeyIdentifier)
        key_id = bytes.hex(subjectKeyIdentifier.value.digest)
        return key_id

    def subject_rfc4514_string(self):
        return self.__certificat.subject.rfc4514_string()

    def subject_rfc4514_string_mq(self):
        """
        Subject avec ordre inverse pour RabbitMQ EXTERNAL
        :return:
        """
        subject = self.subject_rfc4514_string()
        subject_list = subject.split(',')
        subject_list.reverse()
        return ','.join(subject_list)

    @property
    def authority_key_identifier(self):
        authorityKeyIdentifier = self.certificat.extensions.get_extension_for_class(AuthorityKeyIdentifier)
        key_id = bytes.hex(authorityKeyIdentifier.value.key_identifier)
        return key_id

    @property
    def is_root_ca(self):
        return self.is_ca and self.authority_key_identifier == self.subject_key_identifier

    @property
    def is_ca(self):
        try:
            basic_constraints = self.certificat.extensions.get_extension_for_class(BasicConstraints)
            if basic_constraints is not None:
                return basic_constraints.value.ca
            return False
        except ExtensionNotFound:
            return False

    @property
    def _is_valid_at_current_time(self):
        now = datetime.datetime.utcnow()

        # Note : utilisation de pytz pour transformer la date vers le format datetime python3
        #        cryptography utilise un format susceptible a epochalypse sur .timestamp()
        #        https://en.wikipedia.org/wiki/Year_2038_problem
        try:
            is_valid_from = (now > pytz.utc.localize(self.__certificat.not_valid_before))
            is_valid_to = (now < pytz.utc.localize(self.__certificat.not_valid_after))
        except TypeError:
            is_valid_from = (now > self.__certificat.not_valid_before)
            is_valid_to = (now < self.__certificat.not_valid_after)

        return is_valid_from and is_valid_to

    def date_valide_concat(self):
        date_brute = self.__certificat.not_valid_before
        date_formatte = date_brute.strftime('%Y%m%d%H%M%S')
        return date_formatte

    def date_valide(self):
        return self._is_valid_at_current_time

    @property
    def est_verifie(self):
        return self.__est_verifie

    def set_est_verifie(self, flag):
        self.__est_verifie = flag

    def formatter_subject(self):
        sujet_dict = {}

        sujet = self.__certificat.subject
        for elem in sujet:
            sujet_dict[elem.oid._name] = elem.value

        return sujet_dict

    def chaine_enveloppes(self):
        enveloppes = []

        for p in self.__chaine_pem:
            enveloppe = EnveloppeCertificat.from_pem(p)
            enveloppes.append(enveloppe)

        return enveloppes

    def chaine_pem(self):
        return self.__chaine_pem

    @property
    def fingerprint_cle_publique(self) -> str:
        pk = self.certificat.public_key()
        pem = pk.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        pem_bytes = ''.join(pem.strip().decode('utf-8').split('\n')[1:-1]).encode('utf-8')
        pk_bytes = base64.b64decode(pem_bytes)
        return hacher(pk_bytes, hashing_code=EnveloppeCertificat.HASH_FINGERPRINT, encoding=EnveloppeCertificat.ENCODING_FINGERPRINT)

    def calculer_expiration(self):
        date_expiration = self.not_valid_after

        if date_expiration is None:
            # Le certificat n'a pas de date d'expiration
            return {'expire': False, 'renouveler': False}

        date_courante = datetime.datetime.now(tz=pytz.UTC)
        est_expire = date_expiration < date_courante

        # Calculer 2/3 de la duree du certificat
        not_valid_before = self.not_valid_before
        if not_valid_before is None:
            date_renouvellement = date_expiration - datetime.timedelta(days=2)
        else:
            delta_fin_debut = date_expiration.timestamp() - not_valid_before.timestamp()
            epoch_deux_tiers = delta_fin_debut / 3 * 2 + not_valid_before.timestamp()
            date_renouvellement = datetime.datetime.fromtimestamp(epoch_deux_tiers, tz=pytz.UTC)

        peut_renouveler = date_renouvellement < date_courante

        return {'expire': est_expire, 'renouveler': peut_renouveler}

    def get_public_x25519(self) -> X25519PublicKey:
        public_key = self.certificat.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                                               format=serialization.PublicFormat.Raw)

        cle_nacl_verifykey = VerifyKey(public_key).to_curve25519_public_key()
        x25519_public_key = X25519PublicKey.from_public_bytes(cle_nacl_verifykey.encode())

        return x25519_public_key

    def chiffrage_asymmetrique(self, cle_secrete):
        cle_asym = chiffrer_cle_ed25519(self, cle_secrete)
        fingerprint = self.fingerprint
        return cle_asym, fingerprint

    def is_rsa(self):
        public_key = self.__certificat.public_key()
        est_rsa = isinstance(public_key, rsa.RSAPublicKey)
        return est_rsa

    def is_ed25519(self):
        public_key = self.__certificat.public_key()
        est_ed25519 = isinstance(public_key, ed25519.Ed25519PublicKey)
        return est_ed25519

    def __str__(self):
        return 'EnveloppeCertificat %s (%s) ' % (self.fingerprint, self.subject_rfc4514_string())

    def __hash__(self):
        return hash(self.__fingerprint)

    def __eq__(self, other):
        if isinstance(other, EnveloppeCertificat):
            return other.__fingerprint == self.__fingerprint
        else:
            return False


def trouver_idmg(enveloppe: EnveloppeCertificat) -> str:

    # Verifier si cert est root CA (doit calculer idmg)
    if enveloppe.is_root_ca:
        # Calculer IDMG
        idmg = encoder_idmg_cert(enveloppe.certificat)
    else:
        # Utiliser SKID Organization
        idmg = enveloppe.subject_organization_name

    return idmg


def calculer_fingerprint(certificat):
    """
    Calcule le fingerprint d'un certificat.
    :param certificat:
    :return:
    """

    hashing_code = HASH_CODES[EnveloppeCertificat.HASH_FINGERPRINT]
    hash_method = map_code_to_hashes(hashing_code)
    digest = certificat.fingerprint(hash_method)
    mh = multihash.encode(digest, EnveloppeCertificat.HASH_FINGERPRINT)
    mb = multibase.encode(EnveloppeCertificat.ENCODING_FINGERPRINT, mh)
    return mb.decode('utf-8')


def split_chaine_certificats(pem_str: Union[str, bytes]):
    """
    Split une chaine de certificats (PEM format str)
    :param pem_str:
    :return:
    """
    if isinstance(pem_str, bytes):
        pem_str = pem_str.decode('utf-8')
    chaine_certs = [c.strip() + '\n' + END_CERTIFICATE for c in pem_str.split(END_CERTIFICATE)]
    return chaine_certs[0:-1]  # Dernier est juste un END CERTIFICATE


# ---- IDMG ----

# Version courante de IDMG
IDMG_VERSION_ACTIVE = 2
IDMG_VERSION_PACK = {
    1: '=B28sI',
    2: {'header': '=BI'}
}

IDMG_ENCODING = 'base58btc'
IDMG_HASH_FUNCTION = 'blake2s-256'


# def encoder_idmg(certificat_pem: str, version=IDMG_VERSION_ACTIVE):
#     return _encoder_idmg(certificat_pem, version)


def encoder_idmg_cert(cert_x509: Certificate, version=IDMG_VERSION_ACTIVE):
    return _encoder_idmg_cert(cert_x509, version, IDMG_HASH_FUNCTION)


def verifier_idmg(idmg: str, certificat_pem: str):
    return _verifier_idmg(idmg, certificat_pem)


def _encoder_idmg(certificat_pem: str, version=IDMG_VERSION_ACTIVE):
    cert_x509 = load_pem_x509_certificate(certificat_pem.encode('utf-8'), default_backend())
    return encoder_idmg_cert(cert_x509, version)


def _encoder_idmg_cert(cert_x509: Certificate, version=IDMG_VERSION_ACTIVE, hashing_code: Union[int, str] = IDMG_HASH_FUNCTION):
    if isinstance(hashing_code, str):
        hashing_code = HASH_CODES[hashing_code]
    hashing_function = map_code_to_hashes(hashing_code)
    digest_fingerprint = cert_x509.fingerprint(hashing_function)

    # Encoder hachage dans un multihash
    mh = multihash.encode(digest_fingerprint, hashing_code)

    # Note : utilisation de pytz pour transformer la date vers le format datetime python3
    #        cryptography utilise un format susceptible a epochalypse sur .timestamp()
    #        https://en.wikipedia.org/wiki/Year_2038_problem
    date_exp = pytz.utc.localize(cert_x509.not_valid_after)
    date_exp_int = int(math.ceil(float(date_exp.timestamp()) / 1000.0))

    version_info = IDMG_VERSION_PACK[version]
    header_struct = version_info['header']

    valeur_combinee = struct.pack(header_struct, version, date_exp_int)
    valeur_combinee = valeur_combinee + mh

    mb = multibase.encode(IDMG_ENCODING, valeur_combinee)

    return mb.decode('utf-8')


def _verifier_idmg(idmg: str, certificat_pem: str):
    """
    Verifie la correspondance du idmg avec un certificat
    :param idmg: IDMG a verifier
    :param certificat_pem: Certificat qui devrait correspondre au IDMG
    :return:
    :raises: IdmgInvalide si le Idmg ne correspond pas au certificat
    """
    # Extraire la version
    # valeur = base58.b58decode(idmg)
    try:
        valeur = multibase.decode(idmg)
    except ValueError:
        # Probablement version 1 sans multibase
        # Tenter d'extraire directement en base58
        valeur = base58.b58decode(idmg)

    version = int(valeur[0])

    version_info = IDMG_VERSION_PACK[version]

    if version == 1:
        # Version 1 - 33 bytes en base58, hachage SHA512_224
        (version, digest_recu, date_exp_int_recu) = struct.unpack(version_info, valeur)
        hashing_function = hashes.SHA512_224()
    elif version == 2:
        # Version 2 - encodage multibase, 5 bytes header + multihash
        header_struct = version_info['header']
        header_size = struct.Struct(header_struct).size
        (version, date_exp_int_recu) = struct.unpack(header_struct, valeur[0:header_size])
        mh_bytes = valeur[header_size:]
        mh = multihash.decode(mh_bytes)
        hashing_code = mh.code
        hashing_function = map_code_to_hashes(hashing_code)
        digest_recu = mh.digest
    else:
        raise IdmgInvalide("Version non supportee : %d" % version)

    cert_x509 = load_pem_x509_certificate(certificat_pem.encode('utf-8'), default_backend())
    digest_fingerprint_calcule = cert_x509.fingerprint(hashing_function)
    if digest_recu != digest_fingerprint_calcule:
        raise IdmgInvalide("IDMG ne correspond pas au certificat")

    # Note : utilisation de pytz pour transformer la date vers le format datetime python3
    #        cryptography utilise un format susceptible a epochalypse sur .timestamp()
    #        https://en.wikipedia.org/wiki/Year_2038_problem
    date_exp = pytz.utc.localize(cert_x509.not_valid_after)
    date_exp_int = int(math.ceil(float(date_exp.timestamp()) / 1000.0))

    if date_exp_int_recu != date_exp_int:
        raise IdmgInvalide("IDMG fourni en parametre est invalide - date expiration mismatch")


def expiration_idmg(idmg: str):
    """
    Retourne la date d'expiration du IDMG
    :param idmg: IDMG a verifier
    :return:
    :raises: IdmgInvalide si version non supportee
    """
    # Extraire la version
    # valeur = base58.b58decode(idmg)
    try:
        valeur = multibase.decode(idmg)
    except ValueError:
        # Probablement version 1 sans multibase
        # Tenter d'extraire directement en base58
        valeur = base58.b58decode(idmg)

    version = int(valeur[0])

    version_info = IDMG_VERSION_PACK[version]

    if version == 1:
        # Version 1 - 33 bytes en base58, hachage SHA512_224
        (version, digest_recu, date_exp_int_recu) = struct.unpack(version_info, valeur)
    elif version == 2:
        # Version 2 - encodage multibase, 5 bytes header + multihash
        header_struct = version_info['header']
        header_size = struct.Struct(header_struct).size
        (version, date_exp_int_recu) = struct.unpack(header_struct, valeur[0:header_size])
    else:
        raise IdmgInvalide("Version non supportee : %d" % version)

    date_expiration = datetime.datetime.fromtimestamp(date_exp_int_recu * 1000, pytz.UTC)

    return date_expiration


def preparer_chaine_certificats(pems: Union[str, bytes, list]):
    if isinstance(pems, bytes):
        pems = pems.decode('utf-8')
    if isinstance(pems, str):
        return split_chaine_certificats(pems)
    else:
        return pems


class IdmgInvalide(BaseException):
    pass


class CertificatExpire(BaseException):
    pass
