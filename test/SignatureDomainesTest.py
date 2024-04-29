import unittest

from cryptography.exceptions import InvalidSignature

from millegrilles_messages.chiffrage.SignatureDomaines import SignatureDomaines


class SignatureDomainesTestCase(unittest.TestCase):

    CLE_SECRETE = b"01234567890123456789012345678901"

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


if __name__ == '__main__':
    unittest.main()
