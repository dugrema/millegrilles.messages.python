import json
import logging

from millegrilles_messages.certificats.CertificatsWeb import generer_self_signed_ed25519
from millegrilles_messages.certificats.CertificatsMillegrille import generer_csr_intermediaire, signer_csr_intermediaire, \
    generer_csr_leaf
from millegrilles_messages.certificats.CertificatsConfiguration import signer_configuration
from millegrilles_messages.certificats.Generes import CleCertificat

logger = logging.getLogger(__name__)


def generer_par_config_bare(clecert_intermediaire: CleCertificat):
    idmg = clecert_intermediaire.enveloppe.idmg
    csr_leaf = generer_csr_leaf(idmg, 'test-cert')

    configuration = {'roles': ['test']}
    enveloppe = signer_configuration(clecert_intermediaire, csr_leaf.get_pem_csr(), configuration)
    logger.debug("PEM certificat generer_par_config_bare\n%s" % ''.join(enveloppe.chaine_pem()))


def generer_par_config_all(clecert_intermediaire: CleCertificat):
    idmg = clecert_intermediaire.enveloppe.idmg
    csr_leaf = generer_csr_leaf(idmg, 'test-cert')

    configuration = {
        'roles': ['test', 'test2', 'test3'],
        'domaines': ['domaine1', 'domaine2'],
        'exchanges': ['3.protege', '2.prive', '1.public'],
        'dns': {
            'localhost': True,
            'hostnames': ['mg-dev5', 'mg-dev5.maple.maceroc.com'],
        }
    }
    enveloppe = signer_configuration(clecert_intermediaire, csr_leaf.get_pem_csr(), configuration)
    logger.debug("PEM certificat generer_par_config_all\n%s" % ''.join(enveloppe.chaine_pem()))


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

    generer_par_config_bare(clecert_intermediaire)
    generer_par_config_all(clecert_intermediaire)


if __name__ == '__main__':
    logging.basicConfig()
    logging.getLogger(__name__).setLevel(logging.DEBUG)
    logging.getLogger('millegrilles').setLevel(logging.DEBUG)

    main()
