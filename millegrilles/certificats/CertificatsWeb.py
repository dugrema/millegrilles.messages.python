# Genere des certificats/cles self-signed pour des applications web
from cryptography import x509

from millegrilles.certificats.Generes import CleCertificatGenere, TypeGenere


def generer_self_signed_rsa(server_name: str):
    return __generer_self_signed(server_name, type_genere=TypeGenere.RSA)


def generer_self_signed_ed25519(server_name: str):
    return __generer_self_signed(server_name, type_genere=TypeGenere.ED25519)


def __generer_self_signed(server_name: str, type_genere=TypeGenere.ED25519) -> CleCertificatGenere:
    builder = x509.CertificateBuilder()

    name = x509.Name([
        x509.NameAttribute(x509.name.NameOID.COMMON_NAME, server_name),
        x509.NameAttribute(x509.name.NameOID.ORGANIZATION_NAME, u'MilleGrille'),
    ])
    builder = builder.subject_name(name)
    builder = builder.issuer_name(name)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=0),
        critical=True,
    )

    clecert_genere = CleCertificatGenere.generer_certificat(builder, type_genere=type_genere)

    return clecert_genere
