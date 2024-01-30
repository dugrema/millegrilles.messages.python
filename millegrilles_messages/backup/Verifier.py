import asyncio
import datetime
import logging
import pathlib
import time
import concurrent.futures

from os import listdir, path, rename

from millegrilles_messages.messages.Hachage import VerificateurHachage, ErreurHachage

TAILLE_BUFFER = 64 * 1024


class VerifierRepertoire:

    def __init__(self, repertoire_buckets: str, nombre_threads=4):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__repertoire_buckets = pathlib.Path(repertoire_buckets)
        self.__path_invalides = pathlib.Path(repertoire_buckets, '_invalides')
        self.__nombre_threads = nombre_threads
        self.__compteur = 0
        self.__compteur_err = 0
        self.__compteur_bytes = 0

        self.__nombre_fichiers = 0
        self.__taille_fichiers = 0
        self.__stop_event = asyncio.Event()

        self.__queue_fichiers = asyncio.Queue(maxsize=2*self.__nombre_threads)

    async def run(self):
        await self.calculer_nombre_fichiers()
        debut = datetime.datetime.now()
        print("Debut verification : %s" % debut)
        coros = [
            self.verifier_buckets(),
            self.afficher_progres(),
        ]
        await asyncio.gather(*coros)
        fin = datetime.datetime.now()
        duree = fin - debut
        print("Fin de la verification a %s (duree: %s)" % (fin, duree))

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
            self.afficher_progres_ligne()
            try:
                await asyncio.wait_for(self.__stop_event.wait(), 1)
            except asyncio.TimeoutError:
                pass  # OK

    def afficher_progres_ligne(self):
        pct_progres = int(self.__compteur_bytes / self.__taille_fichiers * 100)
        print('\rProgres {:3d}%: {:d}/{:d} fichiers ({:d}/{:d} bytes) traites, {:d} erreurs'.format(
            pct_progres, self.__compteur, self.__nombre_fichiers, self.__compteur_bytes, self.__taille_fichiers,
            self.__compteur_err),
            end=''
        )

    async def verifier_buckets(self):
        # for bucket in self.__repertoire_buckets.iterdir():
        #     self.verifier_fichiers(bucket)
        coros = [
            self.remplir_queue_thread(),
            self.verifier_fichiers(),
        ]
        await asyncio.gather(*coros)

        await asyncio.sleep(0.1)
        self.afficher_progres_ligne()
        print("\nVerification completee sur %d fichiers" % self.__compteur)
        if self.__compteur_err == 0:
            print("Aucunes erreurs")
        else:
            print("%d erreurs de verification, les fichiers sont deplaces sous %s" % (self.__compteur_err, self.__path_invalides))

    async def verifier_fichiers(self):
        threads_verification = [self.__stop_event.wait()]

        # Creer un thread pool pour l'execution des threads
        executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=self.__nombre_threads,
        )

        # Initialiser le nombre de threads
        for i in range(0, self.__nombre_threads):
            threads_verification.append(self.verification_fichiers_thread(executor))

        await asyncio.wait(threads_verification, return_when=asyncio.FIRST_COMPLETED)

    async def verification_fichiers_thread(self, executor):
        loop = asyncio.get_event_loop()

        while self.__stop_event.is_set() is False:
            task = await self.__queue_fichiers.get()
            nom_bucket = task['nom_bucket']
            fichier = task['fichier']

            # Executer dans une thread separee
            await loop.run_in_executor(executor, self.verifier_fichier, nom_bucket, fichier)

    async def remplir_queue_thread(self):
        """
        Thread qui rempli la queue de fichiers a traiter
        :return:
        """
        nombre_fichiers = 0

        for path_bucket in self.__repertoire_buckets.iterdir():
            nom_bucket = path_bucket.name
            if nom_bucket.startswith('_') or nom_bucket.startswith('.'):
                return  # On ne verifie pas les path caches

            for sub_bucket in path_bucket.iterdir():
                for fichier in sub_bucket.iterdir():
                    nombre_fichiers += 1
                    await self.__queue_fichiers.put({'nom_bucket': nom_bucket, 'fichier': fichier})

        # Attendre que le traitement soit complete
        while self.__compteur != nombre_fichiers:
            await asyncio.sleep(0.5)

        self.__stop_event.set()  # Termine

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
            return True
        except ErreurHachage:
            # self.__logger.error("INVALIDE : %s" % hachage)
            self.marquer_invalide(bucket, path_fichier)
            return False
        finally:
            self.__compteur += 1

    def marquer_invalide(self, bucket: str, path_fichier: pathlib.Path):
        sub_bucket = path_fichier.parent.name
        path_fichier_invalide = pathlib.Path(self.__path_invalides, bucket, sub_bucket, path_fichier.name)
        self.__path_invalides.mkdir(exist_ok=True)
        path_fichier_invalide.parent.parent.mkdir(exist_ok=True)
        path_fichier_invalide.parent.mkdir(exist_ok=True)
        path_fichier.rename(path_fichier_invalide)
        self.__compteur_err = self.__compteur_err + 1


async def main(repertoire: str, threads: int):
    # Clamp nombre de threads entre 1 et 32
    threads = max(1, threads)
    threads = min(32, threads)
    verificateur = VerifierRepertoire(repertoire, nombre_threads=threads)
    await verificateur.run()
