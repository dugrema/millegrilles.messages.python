import logging

from millegrilles.certificats.CertificatsWeb import generer_self_signed_ed25519
from millegrilles.certificats.CertificatsMillegrille import generer_csr_intermediaire, signer_csr_intermediaire, \
    generer_csr_leaf, signer_csr_leaf
from millegrilles.certificats.Generes import CleCertificat

logger = logging.getLogger(__name__)


def main():
    root = generer_self_signed_ed25519('MilleGrilles')
    idmg = root.clecertificat.enveloppe.idmg
    logger.debug("IDMG genere : %s" % idmg)

    csr_intermediaire = generer_csr_intermediaire(idmg, '--instance-id--')
    cle_intermediaire = csr_intermediaire.get_pem_cle()
    password_intermediaire = csr_intermediaire.password
    logger.debug("Cle intermediaire\n%s\nPassword: %s" % (cle_intermediaire, password_intermediaire))
    enveloppe_intermediaire = signer_csr_intermediaire(csr_intermediaire.get_pem_csr(), root.clecertificat)
    chaine_intermediaire = enveloppe_intermediaire.chaine_pem()
    logger.debug("CERT intermediaire\n%s" % ''.join(chaine_intermediaire))

    clecert_intermediaire = CleCertificat(csr_intermediaire.cle_privee, enveloppe_intermediaire)

    csr_leaf = generer_csr_leaf(idmg, 'test-cert')
    cle_leaf = csr_leaf.get_pem_cle()
    logger.debug("Cle leaf\n%s" % cle_leaf)
    enveloppe_leaf = signer_csr_leaf(csr_leaf.get_pem_csr(), clecert_intermediaire, '--leaf--')
    chaine_leaf = enveloppe_leaf.chaine_pem()
    logger.debug("CERT leaf\n%s" % ''.join(chaine_leaf))


if __name__ == '__main__':
    logging.basicConfig()
    logging.getLogger(__name__).setLevel(logging.DEBUG)
    logging.getLogger('millegrilles').setLevel(logging.DEBUG)

    main()
