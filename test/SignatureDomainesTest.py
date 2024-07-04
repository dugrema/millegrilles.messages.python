import binascii
import unittest

from cryptography.exceptions import InvalidSignature

from millegrilles_messages.chiffrage.SignatureDomaines import SignatureDomaines


class SignatureDomainesTestCase(unittest.TestCase):

    CLE_SECRETE = b"01234567890123456789012345678901"

    SIGNATURE_SAMPLE1 = {
        'domaines': ['GrosFichiers'],
        'version': 1,
        'ca': '++W4t8wFP7Y31598yO/D25o8is6fnijE+wAFO1DN8G8',
        'signature': 'aGwfIQR7o2aHXEqkTO04cpXyszwKObigBTDc90G7B80ciTgs1Ir49BxbR588Iae51pzBFKhYPvY2wWKLfS6+CA'
    }

    SIGNATURE_HACHAGE_0x0 = {
        'ca': '5VqzX1kQkmxk7CNKVGiEngYLbz1w+dKNeK1WvJqIdXs',
        'domaines': [
            'GrosFichiers'
        ],
        'signature': 'h2nb4aqjhaU77mAWeowBcc+mRuNOautugmE6ciqo4zyxvz0rEM0yuclQ8k1AlQ9185cL0HXkvFpG0Q+18TM4Dw',
        'version': 1
    }

    def test_signer_domaines(self):
        domaines = ["Domaine 1", "Domaine 2"]
        cle_ca = "DUMMY VALEUR CA"

        signature = SignatureDomaines.signer_domaines(SignatureDomainesTestCase.CLE_SECRETE, domaines, cle_ca)

        self.assertEqual("sWVbPAHZ2Xa9rjRtON4tB+Axt5IYI5DqXjmrhDYaClBrBliOtnFmchCufuW/Au46VRFIwJRwN+/oo6YOnVCmBQ", signature.signature)

    def test_verifier_domaines(self):
        domaines = ["Domaine 1", "Domaine 2"]
        valeurs = {
            'domaines': domaines,
            'signature': 'sWVbPAHZ2Xa9rjRtON4tB+Axt5IYI5DqXjmrhDYaClBrBliOtnFmchCufuW/Au46VRFIwJRwN+/oo6YOnVCmBQ',
            'version': 1,
        }
        signature = SignatureDomaines.from_dict(valeurs)
        signature.verifier(SignatureDomainesTestCase.CLE_SECRETE)

    def test_verifier_invalide(self):
        domaines = ["Domaine 1"]
        valeurs = {
            'domaines': domaines,
            'signature': 'sWVbPAHZ2Xa9rjRtON4tB+Axt5IYI5DqXjmrhDYaClBrBliOtnFmchCufuW/Au46VRFIwJRwN+/oo6YOnVCmBQ',
            'version': 1,
        }
        signature = SignatureDomaines.from_dict(valeurs)

        self.assertRaises(InvalidSignature, signature.verifier, SignatureDomainesTestCase.CLE_SECRETE)

    def test_get_cle_ref(self):
        signature = SignatureDomaines.from_dict(SignatureDomainesTestCase.SIGNATURE_SAMPLE1)
        cle_ref = signature.get_cle_ref()

        self.assertEqual('z27EKL3EpJgvf64jkkm5oajuczHgaBTKg4V1YydBJSwFV', cle_ref)

    def test_signature_hachage_0x0(self):
        signature = SignatureDomaines.from_dict(SignatureDomainesTestCase.SIGNATURE_HACHAGE_0x0)
        cle_ref = signature.get_cle_ref()

        # Verifier qu'on a la valeur '1' inseree apres le z
        # C'est le comportement de multibase sur Rust et Javascript quand le premier byte est 0x0
        self.assertEqual('z13yXNnBiBJLKmyqsUZS9bydXroW7ziQ2krYjZXEdHw7E', cle_ref)


if __name__ == '__main__':
    unittest.main()
