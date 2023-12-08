import asyncio
import logging
import pathlib

from os import listdir, path, rename

from millegrilles_messages.messages.Hachage import VerificateurHachage, ErreurHachage

TAILLE_BUFFER = 64 * 1024


class VerifierRepertoire:

    def __init__(self, repertoire_buckets: str):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__repertoire_buckets = pathlib.Path(repertoire_buckets)
        self.__path_invalides = pathlib.Path(repertoire_buckets, '_invalides')
        self.__compteur = 0
        self.__compteur_err = 0
        self.__compteur_bytes = 0

        self.__nombre_fichiers = 0
        self.__taille_fichiers = 0
        self.__stop_event = asyncio.Event()

    async def run(self):
        await self.calculer_nombre_fichiers()
        coros = [
            asyncio.to_thread(self.verifier_buckets),
            self.afficher_progres(),
        ]
        await asyncio.gather(*coros)

    async def calculer_nombre_fichiers(self):
        nombre_fichiers = 0
        taille_fichiers = 0
        print('Verification du nombre de fichiers sous %s' % self.__repertoire_buckets)
        for bucket in self.__repertoire_buckets.iterdir():
            for sub_bucket in bucket.iterdir():
                for fichier in sub_bucket.iterdir():
                    if fichier.is_file():
                        nombre_fichiers = nombre_fichiers + 1
                        stat = fichier.stat()
                        taille_fichiers = taille_fichiers + stat.st_size

        self.__nombre_fichiers = nombre_fichiers
        self.__taille_fichiers = taille_fichiers
        print('Nombre de fichiers %d, taille totale %d' % (nombre_fichiers, taille_fichiers))

    async def afficher_progres(self):
        while self.__stop_event.is_set() is False:
            pct_progres = int(self.__compteur_bytes / self.__taille_fichiers * 100)
            print('\rProgres {:3d}%: {:d}/{:d} fichiers ({:d}/{:d} bytes) traites, {:d} erreurs'.format(
                pct_progres, self.__compteur, self.__nombre_fichiers, self.__compteur_bytes, self.__taille_fichiers, self.__compteur_err),
                end=''
            )
            try:
                await asyncio.wait_for(self.__stop_event.wait(), 1)
            except asyncio.TimeoutError:
                pass  # OK
        print('')

    def verifier_buckets(self):
        for bucket in self.__repertoire_buckets.iterdir():
            self.verifier_fichiers(bucket)

        print("Verification completee sur %d fichiers" % self.__compteur)
        if self.__compteur_err == 0:
            print("Aucunes erreurs")
        else:
            print("%d erreurs de validation" % self.__compteur_err)

        self.__stop_event.set()  # Termine

    def verifier_fichiers(self, path_bucket: pathlib.Path):
        nom_bucket = path_bucket.name
        if nom_bucket == '_invalides':
            return  # On ne verifie pas les invalides

        for sub_bucket in path_bucket.iterdir():
            for fichier in sub_bucket.iterdir():
                self.verifier_fichier(nom_bucket, fichier)

    def verifier_fichier(self, bucket: str, path_fichier: pathlib.Path):
        nom_fichier = path_fichier.name
        hachage = nom_fichier
        verificateur = VerificateurHachage(hachage)

        with open(path_fichier, 'rb') as fichier:
            buffer = fichier.read(TAILLE_BUFFER)
            while len(buffer) > 0:
                self.__compteur_bytes = self.__compteur_bytes + len(buffer)
                verificateur.update(buffer)
                buffer = fichier.read(TAILLE_BUFFER)

        try:
            verificateur.verify()
            self.__compteur = self.__compteur + 1
            return True
        except ErreurHachage:
            self.__logger.error("INVALIDE : %s" % hachage)
            self.marquer_invalide(bucket, path_fichier)
            return False

    def marquer_invalide(self, bucket: str, path_fichier: pathlib.Path):
        sub_bucket = path_fichier.parent.name
        path_fichier_invalide = pathlib.Path(self.__path_invalides, bucket, sub_bucket, path_fichier.name)
        self.__path_invalides.mkdir(exist_ok=True)
        path_fichier_invalide.parent.parent.mkdir(exist_ok=True)
        path_fichier_invalide.parent.mkdir(exist_ok=True)
        path_fichier.rename(path_fichier_invalide)
        self.__compteur_err = self.__compteur_err + 1


async def main(repertoire: str):
    verificateur = VerifierRepertoire(repertoire)
    await verificateur.run()
