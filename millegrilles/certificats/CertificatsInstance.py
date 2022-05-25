from cryptography.x509.base import CertificateBuilder

from millegrilles.certificats.Generes import EnveloppeCsr
from millegrilles.messages.CleCertificat import CleCertificat
from millegrilles.messages import Constantes
from millegrilles.certificats.Generes import ajouter_exchanges, ajouter_roles


def signer_instance_protege(cle_intermediaire: CleCertificat, csr_pem: str):
    enveloppe_csr = EnveloppeCsr.from_str(csr_pem)
    builder = CertificateBuilder()

    exchanges = [Constantes.SECURITE_PROTEGE, Constantes.SECURITE_PRIVE, Constantes.SECURITE_PUBLIC]
    builder = ajouter_exchanges(builder, exchanges)

    role = 'instance'
    builder = ajouter_roles(builder, role)

    enveloppe_certificat = enveloppe_csr.signer(cle_intermediaire, role, builder=builder)

    return enveloppe_certificat
