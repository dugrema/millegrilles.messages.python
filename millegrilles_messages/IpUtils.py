import socket
from typing import Optional


def get_hostname(fqdn=True):
    if fqdn is True:
        return socket.getfqdn()
    return socket.gethostname()


def get_ip(hostname: Optional[str] = None):
    if hostname is None or hostname == '':
        hostname = 'localhost'

    try:
        adresse_ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        adresse_ip = '127.0.0.1'  # Host inconnu, default a localhost

    if adresse_ip.startswith('127.') or adresse_ip.startswith('172.'):
        # On n'a pas trouve l'adresse, essayer d'ouvrir un socket pour laisser
        # la table de routage trouver la destination.

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Si on est sur le meme hote (hostname == localhost == 127.0.0.1), essayer de connecter a "l'exterieur"
            # Noter que l'adresse est dummy
            s.connect(('10.255.255.255', 1))
            adresse_ip = s.getsockname()[0]

            if adresse_ip.startswith('127') or adresse_ip.startswith('172'):
                # On n'a toujours pas l'adresse, pas bon signe.
                # Derniere chance, revient presque au meme que le 1er test.
                s.close()
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect((hostname, 1))
                adresse_ip = s.getsockname()[0]

        except Exception:
            adresse_ip = None
        finally:
            s.close()
    return adresse_ip
