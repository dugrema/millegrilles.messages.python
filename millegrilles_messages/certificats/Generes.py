# Elements generes
import base64
import datetime
import secrets

from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from typing import Optional, Union

from cryptography import x509
from cryptography.x509.base import CertificateBuilder, CertificateSigningRequestBuilder, CertificateSigningRequest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from millegrilles_messages.certificats import Extensions
from millegrilles_messages.messages.EnveloppeCertificat import EnveloppeCertificat
from millegrilles_messages.messages.CleCertificat import CleCertificat

DELTA_INITIAL = datetime.timedelta(seconds=20)  # Initialiser a 20 secondes avant temps courant
ONE_DAY = datetime.timedelta(hours=2)

DUREE_CERT_DEFAUT = datetime.timedelta(days=31)
DUREE_CERT_SELFSIGNED = datetime.timedelta(weeks=20*52)  # 20 ans


class TypeGenere(Enum):
    RSA = 1,
    ED25519 = 2


class EnveloppeCsr:

    def __init__(self, csr_request: CertificateSigningRequest):
        self.__csr_request = csr_request

    @staticmethod
    def from_str(csr_str: str):
        csr = x509.load_pem_x509_csr(csr_str.encode('utf-8'), backend=default_backend())
        if csr.is_signature_valid is False:
            raise Exception('Signature CSR invalide')
        return EnveloppeCsr(csr)

    @staticmethod
    def from_file(path_csr: str):
        with open(path_csr, 'r') as fichier:
            csr_str = fichier.read()
        return EnveloppeCsr.from_str(csr_str)

    @property
    def csr(self):
        return self.__csr_request

    @property
    def cn(self):
        cn_val = self.__csr_request.subject.get_attributes_for_oid(x509.name.NameOID.COMMON_NAME)
        val = cn_val.pop()
        return val.value

    def get_pem(self) -> str:
        return self.csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    @property
    def cle_publique(self) -> bytes:
        return self.__csr_request.public_key().public_bytes(serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

    def signer(self, cle_signature: CleCertificat, role: str,
               builder: Optional[CertificateBuilder] = None, duree=DUREE_CERT_DEFAUT):

        if builder is None:
            builder = CertificateBuilder()

        idmg = cle_signature.enveloppe.idmg
        subject = self.__csr_request.subject
        cle_publique = self.__csr_request.public_key()

        autorite = cle_signature.enveloppe.certificat

        cn = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        subject = x509.Name([
            x509.NameAttribute(x509.name.NameOID.COMMON_NAME, cn),
            x509.NameAttribute(x509.name.NameOID.ORGANIZATIONAL_UNIT_NAME, role),
            x509.NameAttribute(x509.name.NameOID.ORGANIZATION_NAME, idmg),
        ])

        now = datetime.datetime.utcnow()

        builder = builder.subject_name(subject)
        builder = builder.issuer_name(autorite.subject)
        builder = builder.not_valid_before(now - DELTA_INITIAL)
        builder = builder.not_valid_after(now + duree)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(cle_publique)

        cle_publique_signature = cle_signature.enveloppe.certificat.public_key()
        aki = x509.SubjectKeyIdentifier.from_public_key(cle_publique_signature)
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier(aki.digest, None, None),
            critical=False
        )

        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(cle_publique),
            critical=False
        )

        if cle_signature.enveloppe.is_root_ca is False:
            chaine = cle_signature.enveloppe.chaine_pem()
        else:
            chaine = None
        enveloppe = signer_certificat(builder, cle_signature.private_key, chaine)
        return enveloppe


class CleCsrGenere:

    def __init__(self, csr_request: CertificateSigningRequest, cle_privee, password: Optional[str] = None):
        self.__enveloppe_csr = EnveloppeCsr(csr_request)
        self.__cle_privee = cle_privee
        self.__password = password

    @staticmethod
    def build(cn: str, idmg: Optional[str] = None, builder: Optional[CertificateSigningRequestBuilder] = None, generer_password=False,
              type_genere=TypeGenere.ED25519, keysize=2048):

        if builder is None:
            builder = CertificateSigningRequestBuilder()

        # Generer une cle
        if type_genere == TypeGenere.RSA:
            cle_privee, password = generer_cle_rsa(generer_password=generer_password, keysize=keysize)
        elif type_genere == TypeGenere.ED25519:
            # Va utilise type par defaut (EdDSA25519)
            cle_privee, password = generer_cle_ed25519(generer_password=generer_password)
        else:
            raise TypeAlgorithmeInconnu()

        subject = [x509.NameAttribute(x509.name.NameOID.COMMON_NAME, cn)]
        if idmg is not None:
            subject.append(x509.NameAttribute(x509.name.NameOID.ORGANIZATION_NAME, idmg))
        builder = builder.subject_name(x509.Name(subject))

        request = builder.sign(cle_privee, None, default_backend())

        return CleCsrGenere(request, cle_privee, password)

    @staticmethod
    def from_str(csr_str: str, cle: str, password: Optional[str] = None):
        password_bytes = None
        if password is not None:
            password_bytes = password.encode('utf-8')

        csr = x509.load_pem_x509_csr(csr_str.encode('utf-8'), backend=default_backend())

        cle_privee = serialization.load_pem_private_key(
            cle.encode('utf-8'),
            password=password_bytes,
            backend=default_backend()
        )

        return CleCsrGenere(csr, cle_privee, password)

    @staticmethod
    def from_files(path_csr: str, path_cle: str, password: Optional[str], path_password: Optional[str] = None):
        with open(path_csr, 'r') as fichier:
            csr_str = fichier.read()

        with open(path_cle, 'r') as fichier:
            cle_str = fichier.read()

        if path_password is not None:
            with open(path_password, 'r') as fichier:
                password = fichier.read().strip()

        return CleCsrGenere.from_str(csr_str, cle_str, password)

    def get_pem_csr(self) -> str:
        return self.__enveloppe_csr.get_pem()

    def get_pem_cle(self) -> str:
        if self.__password is not None:
            cle_privee_bytes = self.__cle_privee.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(self.__password.encode('utf-8'))
            )
        else:
            cle_privee_bytes = self.__cle_privee.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            )

        return cle_privee_bytes.decode('utf-8')

    @property
    def cle_privee(self):
        return self.__cle_privee

    @property
    def cle_publique(self):
        return self.__enveloppe_csr.cle_publique

    @property
    def password(self) -> Optional[str]:
        return self.__password

    def signer(self, cle_signature: CleCertificat, idmg: str, role: str,
               builder: Optional[CertificateBuilder] = None, duree=DUREE_CERT_DEFAUT):

        enveloppe = self.__enveloppe_csr.signer(cle_signature, idmg, role, builder, duree)
        clecertificat = CleCertificat(self.__cle_privee, enveloppe)
        clecertificat_genere = CleCertificatGenere(clecertificat, self.__password)

        return clecertificat_genere


class CleCertificatGenere:

    def __init__(self, clecertificat: CleCertificat, password: Optional[str]):
        self.__clecert = clecertificat
        self.__password = password

    @property
    def clecertificat(self) -> CleCertificat:
        return self.__clecert

    @staticmethod
    def generer_certificat(builder: CertificateBuilder, type_genere=TypeGenere.ED25519, generer_password=False,
                           keysize=2048, not_valid_before=None, not_valid_after=None):
        """
        Generer un certificat self-signed
        :param builder:
        :param type_genere:
        :param generer_password:
        :param keysize:
        :param not_valid_before:
        :param not_valid_after:
        :return:
        """
        if not_valid_before is None:
            not_valid_before = datetime.datetime.utcnow() - DELTA_INITIAL
        if not_valid_after is None:
            not_valid_after = datetime.datetime.utcnow() + DUREE_CERT_DEFAUT
        builder = builder.not_valid_before(not_valid_before)
        builder = builder.not_valid_after(not_valid_after)
        builder = builder.serial_number(x509.random_serial_number())

        if type_genere == TypeGenere.RSA:
            cle_privee, password = generer_cle_rsa(generer_password=generer_password, keysize=keysize)
        elif type_genere == TypeGenere.ED25519:
            # Va utilise type par defaut (EdDSA25519)
            cle_privee, password = generer_cle_ed25519(generer_password=generer_password)
        else:
            raise TypeAlgorithmeInconnu()

        cle_publique = cle_privee.public_key()
        builder = builder.public_key(cle_publique)

        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(cle_publique),
            critical=False
        )

        ski = x509.SubjectKeyIdentifier.from_public_key(cle_publique)
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier(
                ski.digest,
                None,
                None
            ),
            critical=False
        )

        enveloppe = signer_certificat(builder, cle_privee, password)
        clecertificat = CleCertificat(cle_privee, enveloppe)
        return CleCertificatGenere(clecertificat, password)

    def get_pem_certificat(self) -> list:
        enveloppe = self.__clecert.enveloppe
        return enveloppe.chaine_pem()

    def get_pem_cle(self) -> str:
        return self.__clecert.private_key_bytes(self.__password).decode('utf-8')

    @property
    def password(self):
        return self.__password


def signer_certificat(builder: CertificateBuilder, cle_privee_signature,
                      chaine_intermediaire: Optional[list] = None) -> EnveloppeCertificat:

    if isinstance(cle_privee_signature, RSAPrivateKey):
        certificate = builder.sign(
            private_key=cle_privee_signature,
            algorithm=hashes.SHA512(),
            backend=default_backend()
        )
    elif isinstance(cle_privee_signature, Ed25519PrivateKey):
        certificate = builder.sign(
            private_key=cle_privee_signature,
            algorithm=None,
            backend=default_backend()
        )
    else:
        raise TypeAlgorithmeInconnu()

    enveloppe = EnveloppeCertificat.from_certificate(certificate, chaine_intermediaire)

    return enveloppe


def generer_cle_rsa(generer_password=False, keysize=2048, public_exponent=65537):
    if generer_password:
        password = base64.b64encode(secrets.token_bytes(32)).decode('utf-8').replace('=', '')
    else:
        password = None

    private_key = rsa.generate_private_key(
       public_exponent=public_exponent,
       key_size=keysize,
       backend=default_backend()
    )

    return private_key, password


def generer_cle_ed25519(generer_password=False):
    if generer_password:
        password = base64.b64encode(secrets.token_bytes(32)).decode('utf-8').replace('=', '')
    else:
        password = None

    private_key = Ed25519PrivateKey.generate()

    return private_key, password


class TypeAlgorithmeInconnu(Exception):
    pass


def ajouter_exchanges(builder: CertificateBuilder, exchanges: Union[str, list]) -> CertificateBuilder:
    oid = Extensions.EXCHANGES_OID
    if isinstance(exchanges, str):
        exchanges = [exchanges]
    value = (','.join(exchanges).encode('utf-8'))
    return builder.add_extension(x509.UnrecognizedExtension(oid, value), critical=False)


def ajouter_roles(builder: CertificateBuilder, roles: Union[str, list]) -> CertificateBuilder:
    oid = Extensions.ROLES_OID
    if isinstance(roles, str):
        roles = [roles]
    value = (','.join(roles)).encode('utf-8')
    return builder.add_extension(x509.UnrecognizedExtension(oid, value), critical=False)


def ajouter_domaines(builder: CertificateBuilder, domaines: Union[str, list]) -> CertificateBuilder:
    oid = Extensions.DOMAINES_OID
    if isinstance(domaines, str):
        domaines = [domaines]
    value = (','.join(domaines)).encode('utf-8')
    return builder.add_extension(x509.UnrecognizedExtension(oid, value), critical=False)


def ajouter_dns(builder: CertificateBuilder, hostnames: list = None, localhost=False) -> CertificateBuilder:

    liste = list()

    if hostnames is not None:
        liste.extend([x509.DNSName(u'%s' % h) for h in hostnames])

    if localhost is True:
        liste.extend([
            x509.DNSName(u'localhost'),
            x509.IPAddress(IPv4Address('127.0.0.1')),
            x509.IPAddress(IPv6Address('::1')),
        ])

    # Ajouter noms DNS valides pour MQ
    if len(liste) > 0:
        builder = builder.add_extension(x509.SubjectAlternativeName(liste), critical=False)

    return builder


def ajouter_delegation_globale(builder: CertificateBuilder, delegation: str) -> CertificateBuilder:
    oid = Extensions.DELEGATION_GLOBALE_OID
    value = delegation.encode('utf-8')
    return builder.add_extension(x509.UnrecognizedExtension(oid, value), critical=False)


def ajouter_user_id(builder: CertificateBuilder, user_id: str) -> CertificateBuilder:
    oid = Extensions.USERID_OID
    value = user_id.encode('utf-8')
    return builder.add_extension(x509.UnrecognizedExtension(oid, value), critical=False)
