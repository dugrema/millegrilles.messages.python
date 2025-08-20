# Genere des certificats/cles self-signed pour des applications web
import datetime
from ipaddress import IPv4Address, IPv6Address

from cryptography import x509
from cryptography.x509 import CertificateBuilder

from millegrilles_messages.certificats.Generes import CleCertificatGenere, TypeGenere, CleCsrGenere, ajouter_dns


def generer_self_signed_rsa(server_name: str):
    return __generer_self_signed(server_name, type_genere=TypeGenere.RSA, path_length=1)


def generer_self_signed_ed25519(server_name: str):
    return __generer_self_signed(server_name, type_genere=TypeGenere.ED25519)


def __generer_self_signed(server_name: str, type_genere=TypeGenere.ED25519, path_length=0) -> CleCertificatGenere:
    builder = x509.CertificateBuilder()

    # Generer date precedent 2 jours pour faciliter l'upgrade vers un certificat signe (e.g. Let's Encrypt)
    date_now = datetime.datetime.utcnow() - datetime.timedelta(days=2)
    date_not_valid_before = datetime.datetime(year=date_now.year, month=date_now.month, day=date_now.day)
    date_not_valid_after = datetime.datetime.utcnow() + datetime.timedelta(days=730)

    name = x509.Name([
        x509.NameAttribute(x509.name.NameOID.COMMON_NAME, server_name),
        x509.NameAttribute(x509.name.NameOID.ORGANIZATION_NAME, u'MilleGrille'),
    ])
    builder = builder.subject_name(name)
    builder = builder.issuer_name(name)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=path_length),
        critical=True,
    )

    clecert_genere = CleCertificatGenere.generer_certificat(
        builder, type_genere=type_genere,
        not_valid_before=date_not_valid_before,
        not_valid_after=date_not_valid_after)

    return clecert_genere


def signer_rsa_web(server_name: str, ca: CleCertificatGenere, hostnames: list[str]):
    liste = list()
    liste.extend([x509.DNSName(u'%s' % h) for h in hostnames])

    # Add valid DNS for web server
    liste.extend([
        x509.DNSName(u'localhost'),
        x509.DNSName(u'nginx'),
        x509.IPAddress(IPv4Address('127.0.0.1')),
        x509.IPAddress(IPv6Address('::1')),
    ])

    enveloppe_csr = CleCsrGenere.build(server_name, type_genere=TypeGenere.RSA, keysize=4096)

    date_now = datetime.datetime.utcnow() - datetime.timedelta(days=2)
    date_not_valid_before = datetime.datetime(year=date_now.year, month=date_now.month, day=date_now.day)

    builder = CertificateBuilder()
    builder = builder.add_extension(x509.SubjectAlternativeName(liste), critical=False)
    clecert_genere = enveloppe_csr.signer(ca.clecertificat, 'web', duree=datetime.timedelta(days=730), builder=builder,
                                          not_before=date_not_valid_before)

    return clecert_genere
