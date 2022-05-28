import logging

from millegrilles_messages.messages.EnveloppeCertificat import EnveloppeCertificat

PATH_CA = '/home/mathieu/mgdev/certs/pki.millegrille'
PATH_CORE = '/home/mathieu/mgdev/certs/pki.core.cert'

logger = logging.getLogger(__name__)


def load_certs():
    enveloppe_ca = EnveloppeCertificat.from_file(PATH_CA)
    logger.debug('IDMG cert CA : %s' % enveloppe_ca.idmg)
    logger.debug('Fingerprint cert CA : %s' % enveloppe_ca.fingerprint)

    enveloppe_core = EnveloppeCertificat.from_file(PATH_CORE)
    logger.debug('IDMG cert Core : %s' % enveloppe_core.idmg)
    logger.debug('Fingerprint cert core : %s' % enveloppe_core.fingerprint)
    logger.debug('Exchanges cert core : %s' % enveloppe_core.get_exchanges)
    logger.debug('x25519 public key cert core : %s' % enveloppe_core.get_public_x25519())


def main():
    logging.basicConfig()
    logging.getLogger(__name__).setLevel(logging.DEBUG)
    logging.getLogger('millegrilles').setLevel(logging.DEBUG)

    load_certs()


if __name__ == '__main__':
    main()
