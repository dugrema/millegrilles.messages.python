import logging

from cryptography.x509 import BasicConstraints
from cryptography.x509.base import CertificateBuilder

from millegrilles.certificats.CertificatsWeb import generer_self_signed_ed25519
# from millegrilles.certificats.CertificatIntermediaire import generer_csr_intermediaire
from millegrilles.certificats.Generes import CleCsrGenere, CleCertificat, EnveloppeCsr

logger = logging.getLogger(__name__)


def generer_csr_intermediaire(idmg):
    csr_genere = CleCsrGenere.build(idmg, '--instance-id--', generer_password=True)
    logger.debug("CSR intermediaire PEM\n%s" % csr_genere.get_pem_csr())
    return csr_genere


def signer_csr_intermediaire(csr_pem: str, root_genere: CleCertificat):
    builder = CertificateBuilder()
    builder = builder.add_extension(BasicConstraints(ca=True, path_length=None), critical=True)
    enveloppe_csr = EnveloppeCsr.from_str(csr_pem)
    idmg = root_genere.enveloppe.idmg
    enveloppe_certificat = enveloppe_csr.signer(root_genere, idmg, 'intermediaire', builder=builder)
    return enveloppe_certificat


def generer_csr_leaf(idmg):
    csr_genere = CleCsrGenere.build(idmg, 'test-cert')
    logger.debug("CSR leaf PEM\n%s" % csr_genere.get_pem_csr())
    return csr_genere


def signer_csr_leaf(csr_pem: str, intermediaire: CleCertificat):
    enveloppe_csr = EnveloppeCsr.from_str(csr_pem)
    idmg = intermediaire.enveloppe.idmg
    enveloppe_certificat = enveloppe_csr.signer(intermediaire, idmg, '--leaf--')
    return enveloppe_certificat


def main():
    root = generer_self_signed_ed25519('MilleGrilles')
    idmg = root.clecertificat.enveloppe.idmg
    logger.debug("IDMG genere : %s" % idmg)

    csr_intermediaire = generer_csr_intermediaire(idmg)
    cle_intermediaire = csr_intermediaire.get_pem_cle()
    password_intermediaire = csr_intermediaire.password
    logger.debug("Cle intermediaire\n%s\nPassword: %s" % (cle_intermediaire, password_intermediaire))
    enveloppe_intermediaire = signer_csr_intermediaire(csr_intermediaire.get_pem_csr(), root.clecertificat)
    chaine_intermediaire = enveloppe_intermediaire.chaine_pem()
    logger.debug("CERT intermediaire\n%s" % ''.join(chaine_intermediaire))

    clecert_intermediaire = CleCertificat(csr_intermediaire.cle_privee, enveloppe_intermediaire)

    csr_leaf = generer_csr_leaf(idmg)
    cle_leaf = csr_leaf.get_pem_cle()
    logger.debug("Cle leaf\n%s" % cle_leaf)
    enveloppe_leaf = signer_csr_leaf(csr_leaf.get_pem_csr(), clecert_intermediaire)
    chaine_leaf = enveloppe_leaf.chaine_pem()
    logger.debug("CERT leaf\n%s" % ''.join(chaine_leaf))


if __name__ == '__main__':
    logging.basicConfig()
    logging.getLogger(__name__).setLevel(logging.DEBUG)
    logging.getLogger('millegrilles').setLevel(logging.DEBUG)

    main()
