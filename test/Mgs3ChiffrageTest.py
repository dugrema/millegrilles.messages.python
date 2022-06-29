import asyncio

from millegrilles_messages.chiffrage.Mgs3 import CipherMgs3, DecipherMgs3
from millegrilles_messages.messages.EnveloppeCertificat import EnveloppeCertificat
from millegrilles_messages.messages.CleCertificat import CleCertificat


async def test_chiffrage1():

    # Preparation
    enveloppe = charger_enveloppe_millegrille()
    clecert = charger_clecert_instance()
    public_x25519 = enveloppe.get_public_x25519()

    # Chiffrage
    cipher = CipherMgs3(public_x25519)
    data_original = b'Ceci est du data a chiffrer. Je devrais recuperer la meme chose a la fin.'
    data_chiffre = cipher.update(data_original[0:18])
    data_chiffre = data_chiffre + cipher.update(data_original[18:])
    cipher.finalize()

    # Recuperer info dechiffrage
    info_dechiffrage = cipher.get_info_dechiffrage([clecert.enveloppe])
    iv = info_dechiffrage['iv']
    tag = info_dechiffrage['tag']

    # Dechiffrer cle
    cle_chiffree = info_dechiffrage['cles'][clecert.enveloppe.fingerprint]
    cle_secrete = clecert.dechiffrage_asymmetrique(cle_chiffree)

    # Dechiffrer message
    decipher = DecipherMgs3(cle_secrete, iv, tag)
    data_dechiffre = decipher.update(data_chiffre)
    decipher.finalize()

    if data_original != data_dechiffre:
        raise ValueError("Erreur validation chiffrage")


def charger_enveloppe_millegrille() -> EnveloppeCertificat:
    return EnveloppeCertificat.from_file('/var/opt/millegrilles/configuration/pki.millegrille.cert')


def charger_clecert_instance() -> CleCertificat:
    return CleCertificat.from_files('/var/opt/millegrilles/secrets/pki.instance.key', '/var/opt/millegrilles/secrets/pki.instance.cert')


async def main():
    await test_chiffrage1()


if __name__ == '__main__':
    asyncio.run(main())
