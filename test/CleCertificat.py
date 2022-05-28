import logging

from millegrilles_messages.messages.CleCertificat import CleCertificat

PATH_CORE_CERT = '/home/mathieu/mgdev/certs/pki.core.cert'
PATH_CORE_CLE = '/home/mathieu/mgdev/certs/pki.core.key'

logger = logging.getLogger(__name__)


def charger_cle():
    clecert = CleCertificat.from_files(PATH_CORE_CLE, PATH_CORE_CERT)
    logger.debug('cle / cert correspondent : %s' % clecert.cle_correspondent())
    logger.debug('x25519 private key cert core : %s' % clecert.get_private_x25519())

    enveloppe = clecert.enveloppe
    logger.debug('IDMG cert Core : %s' % enveloppe.idmg)
    logger.debug('Fingerprint cert core : %s' % enveloppe.fingerprint)


def main():
    logging.basicConfig()
    logging.getLogger(__name__).setLevel(logging.DEBUG)
    logging.getLogger('millegrilles').setLevel(logging.DEBUG)

    charger_cle()


if __name__ == '__main__':
    main()