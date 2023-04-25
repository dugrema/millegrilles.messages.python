import argparse
import asyncio
import logging

from millegrilles_messages.backup.Backup import main as backup_main
from millegrilles_messages.backup.Restaurer import main as restaurer_main
from millegrilles_messages.backup.Migrer import main as migrer_main
from millegrilles_messages.backup.DemarrerBackup import main as demarrer_backup
from millegrilles_messages.backup.Verifier import main as verifier_main
from millegrilles_messages.backup.ExtracteurGrosFichiers import main as grosfichiers_main


def parse() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Demarrer une application midcompte/certissuer/utils de MilleGrilles")
    parser.add_argument(
        '--verbose', action="store_true", required=False,
        help="Active le logging maximal"
    )

    subparsers = parser.add_subparsers(dest='command', required=True, help="Commandes")

    # Demarrer un backup de transactions
    subparser_demarrer = subparsers.add_parser('demarrer', help='Declencher un processus')
    subparser_demarrer.add_argument('--backup', action='store_true', required=False,
                                    help='Emet un trigger de backup')
    subparser_demarrer.add_argument('--complet', action='store_true', required=False,
                                    help='Force backup complet (avec rotation des archives)')
    subparser_demarrer.add_argument('--regenerer', type=str, required=False,
                                    help='Regenerer le domaine specifie (e.g. GrosFichiers)')

    # Subparser backup
    subparser_backup = subparsers.add_parser('backup', help='Backup de fichiers')
    subparser_backup.add_argument('--source', default='/var/opt/millegrilles_backup',
                                  help='Repertoire source du backup')
    subparser_backup.add_argument('--dest', default='/var/opt/millegrilles_backup/_ARCHIVES',
                                  help='Repertoire destination du backup')
    subparser_backup.add_argument('--ca', default='/var/opt/millegrilles/configuration/pki.millegrille.cert',
                                  help='Certificat de MilleGrille')

    # Subparser restaurer
    subparser_restaurer = subparsers.add_parser('restaurer', help='Restaurer archive')
    subparser_restaurer.add_argument('--cleca', required=True, help='Path/URL du JSON de cle de millegrille')
    subparser_restaurer.add_argument('--workpath', default='/tmp/millegrilles_restaurer',
                                     help='Path/URL de travail pour l''extraction')
    subparser_restaurer.add_argument('--archive', required=False, help='Path/URL de fichier d''archive')
    subparser_restaurer.add_argument('--transactions', action='store_true', required=False, help='Restaurer les transactions avec MQ')
    subparser_restaurer.add_argument('--rechiffrer', action='store_true', required=False,
                                     help='Rechiffrer domaine MaitreDesCles')
    subparser_restaurer.add_argument('--domaine', type=str, required=False,
                                     help='Restaurer le domaine specifie (e.g. GrosFichiers)')
    subparser_restaurer.add_argument('--delai', type=int, required=False,
                                     help='Delai en secondes entre archives (tweak)')

    # Subparser migrer
    subparser_restaurer = subparsers.add_parser('migrer', help='Migrer archive')
    subparser_restaurer.add_argument('--cleca', required=True, help='Path/URL du JSON de cle de millegrille')
    subparser_restaurer.add_argument('--source', required=True, help='Path/URL de source pour les archives a migrer')
    subparser_restaurer.add_argument('--destination', default='/tmp/millegrilles_migrer',
                                     help='Path/URL de destination pour les archives migrees')
    subparser_restaurer.add_argument('--archive', required=False, help='Path/URL de fichier d''archive')
    subparser_restaurer.add_argument('--domaine', type=str, required=False,
                                     help='Migrer le domaine specifie (e.g. GrosFichiers)')

    subparser_demarrer = subparsers.add_parser('verifier', help='Verifier fichiers')
    subparser_demarrer.add_argument('--repertoire', type=str, required=False,
                                    help='Repertoire avec les fichiers a verifier')

    subparser_grosfichiers = subparsers.add_parser('grosfichiers', help='Dechiffrer fichiers')
    subparser_grosfichiers.add_argument('--ca', default='/var/opt/millegrilles/configuration/pki.millegrille.cert',
                                        help='Certificat de MilleGrille')
    subparser_grosfichiers.add_argument('--consignation', default='https://localhost:444', help='URL consignation')
    subparser_grosfichiers.add_argument('--extraction', default='/tmp/grosfichiers', help='Path extraction')

    args = parser.parse_args()
    adjust_logging(args)

    return args


def adjust_logging(args: argparse.Namespace):

    logging_level = logging.INFO

    if args.verbose is True:
        logging_level = logging.DEBUG
        logging.getLogger('millegrilles_messages').setLevel(logging_level)

    loggers = [__name__, 'millegrilles_messages.backup']
    for log in loggers:
        logging.getLogger(log).setLevel(logging_level)


async def demarrer(args: argparse.Namespace):
    command = args.command

    if command == 'demarrer':
        await demarrer_backup(args.backup, args.complet, args.regenerer)
    elif command == 'backup':
        await backup_main(args.source, args.dest, args.ca)
    elif command == 'restaurer':
        await restaurer_main(args.archive, args.workpath, args.cleca,
                             transactions=args.transactions, rechiffrer=args.rechiffrer,
                             domaine=args.domaine, delai=args.delai)
    elif command == 'migrer':
        await migrer_main(args.archive, args.source, args.destination, args.cleca, domaine=args.domaine)
    elif command == 'verifier':
        await verifier_main(args.repertoire)
    elif command == 'grosfichiers':
        await grosfichiers_main(args.ca, args.extraction, args.consignation)
    else:
        raise ValueError('non supporte')


def main():
    """
    Methode d'execution de l'application
    :return:
    """
    logging.basicConfig()
    logging.getLogger(__name__).setLevel(logging.DEBUG)
    logging.getLogger('millegrilles').setLevel(logging.DEBUG)
    logging.getLogger('millegrilles_messages').setLevel(logging.DEBUG)

    args = parse()
    asyncio.run(demarrer(args))


if __name__ == '__main__':
    main()
