from cryptography.x509.base import CertificateBuilder

from millegrilles_messages.certificats.Generes import EnveloppeCsr
from millegrilles_messages.messages.CleCertificat import CleCertificat
from millegrilles_messages.messages import Constantes
from millegrilles_messages.certificats.Generes import ajouter_exchanges, ajouter_roles
from millegrilles_messages.certificats.Generes import DUREE_CERT_DEFAUT


def signer_instance_protege(cle_intermediaire: CleCertificat, csr_pem: str, duree=DUREE_CERT_DEFAUT):
    enveloppe_csr = EnveloppeCsr.from_str(csr_pem)
    builder = CertificateBuilder()

    exchanges = [Constantes.SECURITE_PROTEGE, Constantes.SECURITE_PRIVE, Constantes.SECURITE_PUBLIC]
    builder = ajouter_exchanges(builder, exchanges)

    role = 'instance'
    builder = ajouter_roles(builder, role)

    enveloppe_certificat = enveloppe_csr.signer(cle_intermediaire, role, builder=builder, duree=duree)

    return enveloppe_certificat


def signer_instance_prive(cle_intermediaire: CleCertificat, csr_pem: str, duree=DUREE_CERT_DEFAUT):
    enveloppe_csr = EnveloppeCsr.from_str(csr_pem)
    builder = CertificateBuilder()

    exchanges = [Constantes.SECURITE_PRIVE, Constantes.SECURITE_PUBLIC]
    builder = ajouter_exchanges(builder, exchanges)

    role = 'instance'
    builder = ajouter_roles(builder, role)

    enveloppe_certificat = enveloppe_csr.signer(cle_intermediaire, role, builder=builder, duree=duree)

    return enveloppe_certificat


def signer_instance_public(cle_intermediaire: CleCertificat, csr_pem: str, duree=DUREE_CERT_DEFAUT):
    enveloppe_csr = EnveloppeCsr.from_str(csr_pem)
    builder = CertificateBuilder()

    exchanges = [Constantes.SECURITE_PUBLIC]
    builder = ajouter_exchanges(builder, exchanges)

    role = 'instance'
    builder = ajouter_roles(builder, role)

    enveloppe_certificat = enveloppe_csr.signer(cle_intermediaire, role, builder=builder, duree=duree)

    return enveloppe_certificat
