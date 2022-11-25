from millegrilles_messages.messages.Hachage import Hacheur
import binascii
import multibase

binput = bytearray(b"salut le monde des terres a courir pour des choses en entree")


def test():
    # hacheur = Hacheur('blake2s-256', 'base64')
    hacheur = Hacheur('blake2b-512', 'base64')
    hacheur.update(binput)
    res = hacheur.finalize()
    print("Resultat %s" % res)

    res_decode = multibase.decode(res)
    print("Resultat bin %s" % binascii.hexlify(res_decode))


if __name__ == '__main__':
    test()
