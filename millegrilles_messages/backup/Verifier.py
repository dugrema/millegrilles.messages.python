import logging

from os import listdir, path, rename

from millegrilles_messages.messages.Hachage import VerificateurHachage, ErreurHachage

TAILLE_BUFFER = 32 * 1024


class VerifierRepertoire:

    def __init__(self, repertoire: str):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__repertoire = repertoire

    async def run(self):
        await self.verifier_fichiers()

    async def verifier_fichiers(self):
        compteur = 0
        compteur_err = 0
        for item in listdir(self.__repertoire):
            path_fichier = path.join(self.__repertoire, item)
            if item.endswith('.invalide') is True:
                print("SKIP %s" % item)
            elif item.startswith('z') and path.isfile(path_fichier) is True:
                compteur = compteur + 1
                resultat = await self.verifier_fichier(path_fichier)
                if resultat is False:
                    compteur_err = compteur_err + 1

        print("Verification completee sur %d fichiers" % compteur)
        if compteur_err == 0:
            print("Aucunes erreurs")
        else:
            print("%d erreurs de validation" % compteur_err)

    async def verifier_fichier(self, path_fichier: str):
        nom_fichier = path.basename(path_fichier)
        hachage = nom_fichier.split('.')[0]
        verificateur = VerificateurHachage(hachage)

        with open(path_fichier, 'rb') as fichier:
            buffer = fichier.read(TAILLE_BUFFER)
            while len(buffer) > 0:
                verificateur.update(buffer)
                buffer = fichier.read(TAILLE_BUFFER)

        try:
            verificateur.verify()
            return True
        except ErreurHachage:
            self.__logger.error("INVALIDE : %s, renomme (.invalide)" % hachage)
            rename(path_fichier, '%s.invalide' % path_fichier)
            return False


async def main(repertoire: str):
    verificateur = VerifierRepertoire(repertoire)
    await verificateur.run()
