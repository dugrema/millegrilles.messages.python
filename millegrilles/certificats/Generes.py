# Elements generes
import base64
import datetime
import secrets

from enum import Enum
from typing import Optional

from cryptography import x509
from cryptography.x509.base import CertificateBuilder, CertificateSigningRequestBuilder
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from millegrilles.messages.EnveloppeCertificat import EnveloppeCertificat
from millegrilles.messages.CleCertificat import CleCertificat

DELTA_INITIAL = datetime.timedelta(seconds=20)  # Initialiser a 20 secondes avant temps courant
ONE_DAY = datetime.timedelta(hours=2)

DUREE_CERT_DEFAUT = datetime.timedelta(days=31)
DUREE_CERT_SELFSIGNED = datetime.timedelta(weeks=20*52)  # 20 ans


class TypeGenere(Enum):
    RSA = 1,
    ED25519 = 2


class Csr:

    def __init__(self):
        pass


class CleCsrGenere:

    def __init__(self):
        pass

    @staticmethod
    def generer_csr(builder: CertificateSigningRequestBuilder, type_genere=TypeGenere.ED25519):
        pass

    @staticmethod
    def charger_csr(path_csr: str, path_cle: str):
        pass


class CleCertificatGenere:

    def __init__(self, clecertificat: CleCertificat, password: Optional[str]):
        self.__clecert = clecertificat
        self.__password = password

    @property
    def clecertificat(self) -> CleCertificat:
        return self.__clecert

    @staticmethod
    def generer_certificat(builder: CertificateBuilder, chaine_intermediaire: Optional[list] = None,
                           type_genere=TypeGenere.ED25519, generer_password=False, keysize=2048):

        builder = builder.not_valid_before(datetime.datetime.utcnow() - DELTA_INITIAL)
        builder = builder.not_valid_after(datetime.datetime.utcnow() + DUREE_CERT_DEFAUT)
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

        if type_genere == TypeGenere.RSA:
            certificate = builder.sign(
                private_key=cle_privee,
                algorithm=hashes.SHA512(),
                backend=default_backend()
            )
        elif type_genere == TypeGenere.ED25519:
            certificate = builder.sign(
                private_key=cle_privee,
                algorithm=None,
                backend=default_backend()
            )
        else:
            raise TypeAlgorithmeInconnu()

        enveloppe = EnveloppeCertificat.from_certificate(certificate, chaine_intermediaire)
        clercertificat = CleCertificat(cle_privee, enveloppe)
        clecert_generer = CleCertificatGenere(clercertificat, password)

        return clecert_generer

    def get_pem_certificat(self) -> list:
        enveloppe = self.__clecert.enveloppe
        return enveloppe.chaine_pem()

    def get_pem_cle(self) -> str:
        return self.__clecert.private_key_bytes(self.__password).decode('utf-8')

    @property
    def password(self):
        return self.__password


def generer_cle_rsa(generer_password=False, keysize=2048, public_exponent=65537):
    if generer_password:
        password = base64.b64encode(secrets.token_bytes(16))
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
        password = base64.b64encode(secrets.token_bytes(16))
    else:
        password = None

    private_key = Ed25519PrivateKey.generate()

    return private_key, password


class TypeAlgorithmeInconnu(Exception):
    pass
