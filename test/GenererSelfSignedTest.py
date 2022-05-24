import logging

from millegrilles.certificats.CertificatsWeb import generer_self_signed_rsa, generer_self_signed_ed25519

logger = logging.getLogger(__name__)


def test_rsa():
    clecert_genere = generer_self_signed_rsa('localhost')
    pem_certificat = clecert_genere.get_pem_certificat()
    pem_cle = clecert_genere.get_pem_cle()

    for pem in pem_certificat:
        logger.debug("rsa PEM certificat\n%s" % pem)
    logger.debug("rsa EM cle\n%s" % pem_cle)

    if clecert_genere.password is not None:
        logger.debug("Password : %s" % clecert_genere.password)


def test_ed25519():
    clecert_genere = generer_self_signed_ed25519('localhost')
    pem_certificat = clecert_genere.get_pem_certificat()
    pem_cle = clecert_genere.get_pem_cle()

    for pem in pem_certificat:
        logger.debug("ed25519 PEM certificat\n%s" % pem)
    logger.debug("ed25519 PEM cle\n%s" % pem_cle)

    if clecert_genere.password is not None:
        logger.debug("Password : %s" % clecert_genere.password)


if __name__ == '__main__':
    logging.basicConfig()
    logging.getLogger(__name__).setLevel(logging.DEBUG)
    logging.getLogger('millegrilles').setLevel(logging.DEBUG)

    test_rsa()
    test_ed25519()
