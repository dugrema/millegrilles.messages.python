import asyncio
import datetime
import logging
import pathlib
import time
import concurrent.futures
from asyncio import TaskGroup, QueueFull

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
        self.__thread_files_done = asyncio.Event()

    async def stop_thread(self):
        await self.__stop_event.wait()
        self.__thread_files_done.set()
        for i in range(self.__nombre_threads):
            try:
                self.__queue_fichiers.put_nowait(None)
            except QueueFull:
                pass

    async def run(self):
        await self.calculer_nombre_fichiers()
        debut = datetime.datetime.now()
        print("Debut verification : %s" % debut)
        async with TaskGroup() as group:
            group.create_task(self.verifier_buckets())
            group.create_task(self.afficher_progres())
            group.create_task(self.stop_thread())

        fin = datetime.datetime.now()
        duree = fin - debut
        print("Fin de la verification a %s (duree: %s)" % (fin, duree))

    async def calculer_nombre_fichiers(self):
        nombre_fichiers = 0
        taille_fichiers = 0
        print('Verification du nombre de fichiers sous %s' % self.__repertoire_buckets)
        for bucket in self.__repertoire_buckets.iterdir():
            for fichier in bucket.iterdir():
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

        data_progress = format_size(self.__compteur_bytes)
        data_total = format_size(self.__taille_fichiers)

        print('\rProgres {:3d}%: {:d}/{:d} fichiers ({:s}/{:s}) traites, {:d} erreurs'.format(
            pct_progres, self.__compteur, self.__nombre_fichiers, data_progress, data_total,
            self.__compteur_err),
            end=''
        )

    async def verifier_buckets(self):
        # for bucket in self.__repertoire_buckets.iterdir():
        #     self.verifier_fichiers(bucket)
        async with TaskGroup() as group:
            group.create_task(self.remplir_queue_thread())
            group.create_task(self.verifier_fichiers())

        await asyncio.sleep(0.1)
        self.afficher_progres_ligne()
        print("\nVerification completee sur %d fichiers" % self.__compteur)
        if self.__compteur_err == 0:
            print("Aucunes erreurs")
        else:
            print("%d erreurs de verification, les fichiers sont deplaces sous %s" % (self.__compteur_err, self.__path_invalides))

    async def verifier_fichiers(self):
        # Creer un thread pool pour l'execution des threads
        async with TaskGroup() as group:
            # Initialiser le nombre de threads
            for i in range(0, self.__nombre_threads):
                group.create_task(self.verification_fichiers_thread())

    async def verification_fichiers_thread(self):
        while self.__stop_event.is_set() is False:
            task = await self.__queue_fichiers.get()
            if task is None:
                return  # Stopping
            nom_bucket = task['nom_bucket']
            fichier = task['fichier']

            # Executer dans une thread separee
            await asyncio.to_thread(self.verifier_fichier, nom_bucket, fichier)

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

            for fichier in path_bucket.iterdir():
                nombre_fichiers += 1
                await self.__queue_fichiers.put({'nom_bucket': nom_bucket, 'fichier': fichier})

        # Attendre que le traitement soit complete
        while self.__queue_fichiers.empty() is False:
            await asyncio.sleep(0.5)

        self.__thread_files_done.set()
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

CONST_KiB = 1_000
CONST_MiB = 1_000_000
CONST_GiB = 1_000_000_000
CONST_TiB = 1_000_000_000_000

def format_size(size: int) -> str:
    if size >= CONST_TiB:
        val = size / CONST_TiB
        unit = 'TiB'
    elif size >= CONST_GiB:
        val = size / CONST_GiB
        unit = 'GiB'
    elif size >= CONST_MiB:
        val = size / CONST_MiB
        unit = 'MiB'
    elif size >= CONST_KiB:
        val = size / CONST_KiB
        unit = 'KiB'
    else:
        val = size
        unit = 'bytes'

    val = round(val, 2)
    return f'{val} {unit}'
