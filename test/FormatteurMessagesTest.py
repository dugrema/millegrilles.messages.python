import json
import logging

from millegrilles_messages.messages.CleCertificat import CleCertificat
from millegrilles_messages.messages.FormatteurMessages import SignateurTransactionSimple, FormatteurMessageMilleGrilles

PATH_CORE_CERT = '/home/mathieu/mgdev/certs/pki.core.cert'
PATH_CORE_CLE = '/home/mathieu/mgdev/certs/pki.core.key'

logger = logging.getLogger(__name__)


def formatter_message():
    clecert = CleCertificat.from_files(PATH_CORE_CLE, PATH_CORE_CERT)
    enveloppe = clecert.enveloppe
    idmg = enveloppe.idmg

    signateur = SignateurTransactionSimple(clecert)
    formatteur = FormatteurMessageMilleGrilles(idmg, signateur)

    message_1 = {'valeur': 1, 'texte': 'Du texte.'}
    message_1_signe, uuid_transaction = formatteur.signer_message(message_1)
    message_1_indent = json.dumps(message_1_signe, indent=2)
    logger.debug("Message 1 signe (uuid: %s) : %s" % (uuid_transaction, message_1_indent))


def main():
    logging.basicConfig()
    logging.getLogger(__name__).setLevel(logging.DEBUG)
    logging.getLogger('millegrilles').setLevel(logging.DEBUG)

    formatter_message()


if __name__ == '__main__':
    main()
