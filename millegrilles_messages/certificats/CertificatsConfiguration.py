# Certificats a partir d'une configuration json
import datetime
from typing import Optional

from cryptography.x509.base import CertificateBuilder

from millegrilles_messages.certificats.Generes import EnveloppeCsr, ajouter_roles, ajouter_exchanges, ajouter_domaines, \
    ajouter_user_id, ajouter_delegation_globale, ajouter_dns, DUREE_CERT_DEFAUT
from millegrilles_messages.messages.CleCertificat import CleCertificat
from millegrilles_messages.messages import Constantes


def signer_configuration(cle_intermediaire: CleCertificat, csr_pem: str, configuration: dict):
    enveloppe_csr = EnveloppeCsr.from_str(csr_pem)

    # Le role principal est le premier de la liste
    role = configuration['roles'][0]

    builder = builder_for_application(configuration)

    try:
        duree = datetime.timedelta(seconds=configuration['duree'])
    except (TypeError, KeyError):
        duree = DUREE_CERT_DEFAUT

    enveloppe_certificat = enveloppe_csr.signer(cle_intermediaire, role, builder=builder, duree=duree)

    return enveloppe_certificat


def builder_for_application(configuration: dict):
    builder = CertificateBuilder()

    try:
        builder = ajouter_exchanges(builder, configuration['exchanges'])
    except KeyError:
        pass

    try:
        builder = ajouter_roles(builder, configuration['roles'])
    except KeyError:
        pass

    try:
        builder = ajouter_domaines(builder, configuration['domaines'])
    except KeyError:
        pass

    try:
        configuration_dns = configuration['dns']
        hostnames = configuration_dns.get('hostnames') or None
        localhost = configuration_dns.get('localhost') or False
        builder = ajouter_dns(builder, hostnames, localhost)
    except KeyError:
        pass

    return builder


def builder_for_user(user_id: str, delegation_globale: Optional[str]):
    builder = CertificateBuilder()
    builder = ajouter_user_id(builder, user_id)

    if delegation_globale is not None:
        builder = ajouter_delegation_globale(builder, delegation_globale)

    return builder
