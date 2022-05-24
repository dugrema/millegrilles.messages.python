import logging

from cryptography.x509 import BasicConstraints
from cryptography.x509.base import CertificateBuilder

from millegrilles.certificats.Generes import CleCsrGenere, CleCertificat, EnveloppeCsr

logger = logging.getLogger(__name__)


def generer_csr_intermediaire(idmg: str, cn: str):
    csr_genere = CleCsrGenere.build(idmg, cn, generer_password=True)
    logger.debug("CSR intermediaire PEM\n%s" % csr_genere.get_pem_csr())
    return csr_genere


def signer_csr_intermediaire(csr_pem: str, root_genere: CleCertificat):
    builder = CertificateBuilder()
    builder = builder.add_extension(BasicConstraints(ca=True, path_length=None), critical=True)
    enveloppe_csr = EnveloppeCsr.from_str(csr_pem)
    idmg = root_genere.enveloppe.idmg
    enveloppe_certificat = enveloppe_csr.signer(root_genere, idmg, 'intermediaire', builder=builder)
    return enveloppe_certificat


def generer_csr_leaf(idmg: str, cn: str):
    csr_genere = CleCsrGenere.build(idmg, cn)
    logger.debug("CSR PEM\n%s" % csr_genere.get_pem_csr())
    return csr_genere


def signer_csr_leaf(csr_pem: str, intermediaire: CleCertificat, role: str):
    enveloppe_csr = EnveloppeCsr.from_str(csr_pem)
    idmg = intermediaire.enveloppe.idmg
    enveloppe_certificat = enveloppe_csr.signer(intermediaire, idmg, role)
    return enveloppe_certificat
